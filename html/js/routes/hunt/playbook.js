// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

export default {
  async loadPlaybook(event, index) {
    if ('playbooks' in event || 'playbookLoading' in event || 'playbookErr' in event) return;
    
    const publicId = event?.['rule.uuid'];
    if (!publicId) {
      event.playbookErr = true;
      return;
    }

    event.playbookLoading = true;

    let playbooks;
    let pbErr = false;

    try {
      const response = await this.$root.papi.get(`playbook/detection/${publicId}`);

      playbooks = response.data;
    } catch (e) {
      pbErr = true;
      playbooks = null;
    }

    if (playbooks) {
      this.queryVariableSubstitution(event, playbooks);
      try {
        await this.convertPlaybookQueries(playbooks);
      } catch (error) {
        console.error('Failed to convert playbook queries, continuing with basic data:', error);
        // Continue with playbooks even if conversion fails
      }
    }

    event.playbooks = playbooks;
    event.playbookErr = pbErr;
    delete event.playbookLoading;

    if (playbooks) {
      // answer the questions and
      // stable sort them by results
      let good = []; // has answers
      let bad = [];  // no answers
      let ugly = []; // error
      for (let pb of event.playbooks) {
        for (let q of pb.questions) {
          await this.$nextTick();
          await this.askQuestion(q, event);

          if (q.error) {
            ugly.push(q);
          } else if (q.answers.length > 0) {
            good.push(q);
          } else {
            bad.push(q);
          }
        }
      }

      event.questions = [...good, ...bad, ...ugly];

      this.expandedPlaybookQuestions[index] = [];
      for (let i = 0; i < good.length; i++) {
        this.expandedPlaybookQuestions[index].push(i);
      }
    }
  },
  queryVariableSubstitution(event, playbooks) {
    // Fields that require special array handling
    const arrayFields = ['network.private_ip', 'network.public_ip', 'related.ip'];

    for (let pb of playbooks) {
      for (let question of pb.questions) {
        let q = question.query;
        
        // Find all variables in the query using regex
        const variables = q.match(/\{([^}]+)\}/g) || [];
        
        // Process each variable
        for (const variable of variables) {
          const fieldName = variable.slice(1, -1); // Remove { and }
          let value = event[fieldName] || 'NODATA';
          
          // Special handling for array fields
          if (arrayFields.includes(fieldName) && Array.isArray(value)) {
            // Find the line containing the variable
            const lines = q.split('\n');
            const lineWithVar = lines.findIndex(line => line.includes(variable));
            
            if (lineWithVar !== -1) {
              // Get the field being set (e.g., src_ip or dst_ip)
              const match = lines[lineWithVar].match(/^(\s*)(?:-\s*)?(\w+(?:\.\w+)*(?:\|\w+)*):(?:\s*|$)/);
              if (match) {
                const indent = match[1];
                const field = match[2];
                const originalLine = lines[lineWithVar];
                const hasDash = originalLine.trim().startsWith('-');
                const prefix = hasDash ? '- ' : '';
                const replacement = `${indent}${prefix}${field}:\n${value.map(ip => `${indent}    - ${ip}`).join('\n')}`;
                
                // Replace the entire line
                lines[lineWithVar] = replacement;
                q = lines.join('\n');
                continue;
              }
            }
          }
          
          // Default replacement if not handled as special case
          q = q.replaceAll(variable, value);
        }
        
        question.filledQuery = q;
      }
    }
  },

  async convertPlaybookQueries(playbooks) {
    let queries = playbooks.map((pb) => pb.questions.map((q) => q.filledQuery)).flat();

    if (queries.length === 0) return;

    try {
      let response = await this.$root.papi.post('playbook/convert', queries);
      if (!response || !response.data) {
        console.error('Invalid response from playbook/convert API');
        return;
      }

      let index = 0;
      for (let pb of playbooks) {
        for (let question of pb.questions) {
          if (response.data[index]) {
            question.filledOQL = response.data[index].query;
            question.fields = response.data[index].fields;
          } else {
            console.warn(`No conversion data for question at index ${index}`);
          }
          index++;
        }
      }
    } catch (error) {
      console.error('Error converting playbook queries:', error);
      // Set default values to prevent further errors
      for (let pb of playbooks) {
        for (let question of pb.questions) {
          question.filledOQL = question.filledQuery || '';
          question.fields = [];
        }
      }
    }
  },
  async askQuestion(question, event) {
    if (question.range && question.filledOQL) {
      try {
        const dateRange = this.buildQuestionRange(event, question.range);
        let query = question.filledOQL;
        if (!this.isQuestionAggregate(question)) {
          query = query + ` | sortby @timestamp`;
        }

        let response = await this.$root.papi.get('events/', {
          params: {
            query: query,
            range: dateRange,
            format: this.i18n.timePickerSample,
            zone: this.zone,
            metricLimit: 5,
            eventLimit: 5
          }
        });

        if (this.isQuestionAggregate(question)) {
          let biggest = '';
          for (let field in response.data.metrics) {
            if (field.length > biggest.length) biggest = field;
          }
          if (biggest) {
            question.answers = this.sortAggregateEvents(response.data.metrics[biggest]);
          } else {
            // fallback, less than ideal
            question.answers = response.data.events;
          }
        } else {
          question.answers = response.data.events;
        }
      } catch (e) {
        question.error = true;
        question.answers = [];
      }
    } else {
      // no range specified means we can find the answer on the event
      // but avoid making a circular reference
      const dupe = JSON.parse(JSON.stringify(event));
      question.answers = [{ payload: dupe }];
    }

    let ips = [];
    for (let answer of question.answers) {
      if (answer.payload) {
        for (let v of Object.values(answer.payload)) {
          if (v && typeof v === 'string') {
            ips.push(v);
          }
        }
      } else if (answer.keys) {
        for (let key of answer.keys) {
          ips.push(key);
        }
      }
    }

    this.$root.batchLookup(ips, this);
  },
  sortAggregateEvents(events) {
    events = events.sort((a, b) => b.value - a.value);

    if (events.length > 5) {
      events = events.slice(0, 5);
    }

    return events;
  },
  buildQuestionRange(event, range) {
    if (!range) {
      return '';
    }

    let t = this.getEventTimestamp(event);

    let plusMinus = false;
    let lookingBack = false;

    if (range.startsWith('+/-')) {
      plusMinus = true;
      range = range.substring(3);
    } else if (range.startsWith('-')) {
      lookingBack = true;
      range = range.substring(1);
    }

    let unit = range[range.length - 1].toLowerCase();
    range = range.substring(0, range.length - 1);

    let value = parseInt(range);
    if (isNaN(value)) {
      return '';
    }

    unit = { d: 'days', h: 'hours', m: 'minutes', s: 'seconds' }[unit];
    if (!unit) {
      return '';
    }

    let t1, t2;

    if (plusMinus) {
      t1 = moment.tz(t, this.zone).subtract(value, unit).format(this.i18n.timePickerFormat);
      t2 = moment.tz(t, this.zone).add(value, unit).format(this.i18n.timePickerFormat);
    } else if (lookingBack) {
      t1 = moment.tz(t, this.zone).subtract(value, unit).format(this.i18n.timePickerFormat);
      t2 = moment.tz(t, this.zone).format(this.i18n.timePickerFormat);
    } else {
      t1 = moment.tz(t, this.zone).format(this.i18n.timePickerFormat);
      t2 = moment.tz(t, this.zone).add(value, unit).format(this.i18n.timePickerFormat);
    }

    return `${t1} - ${t2}`;
  },
  getEventTimestamp(event) {
    return event?.['event_data.@timestamp'] || event?.['@timestamp'] || event?.['soc_timestamp'] || '';
  },
  buildHuntQuestionParams(question, event) {
    let payload = {
      name: 'hunt',
      query: {
        q: question.filledOQL,
      },
    };

    if (question.range) {
      payload.query.t = this.buildQuestionRange(event, question.range);
    } else {
      payload.query.t = this.dateToRange(this.getEventTimestamp(event));
    }

    return payload;
  },
  isQuestionAggregate(question) {
    if ('isAggregate' in question) return question.isAggregate;

    const yaml = jsyaml.load(question.query, { schema: jsyaml.FAILSAFE_SCHEMA });
    question.isAggregate = typeof yaml.aggregation === 'string' && yaml.aggregation.toLowerCase() === 'true';

    return question.isAggregate;
  },
  toggleAllQuestions(event, index, expand) {
    if (event.playbookErr) return;

    event = (event || {}).newest || event;

    if (event.playbookLoading || !('questions' in event)) {
      setTimeout(() => {
        this.toggleAllQuestions(event, index, expand);
      }, 100)
      return;
    }

    if (event.questions) {
      if (!Array.isArray(this.expandedPlaybookQuestions[index]) || !expand) this.expandedPlaybookQuestions[index] = [];
      if (expand) {
        for (let i = 0; i < event.questions.length; i++) {
          if (!this.expandedPlaybookQuestions[index].includes(i)) {
            this.expandedPlaybookQuestions[index].push(i);
          }
        }
      }
    }
  },
  pickQuestionColor(question) {
    if (question.error) {
      return 'has-error';
    }

    if (question.answers && question.answers.length > 0) {
      return 'has-answers';
    }

    return 'no-data';
  }
};