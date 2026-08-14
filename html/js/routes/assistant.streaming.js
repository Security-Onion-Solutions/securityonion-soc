// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Assistant page methods: message sending, SSE stream parsing/assembly, the
// callAIAPI streaming loop, tool-execution streaming, and delegation (sub-agent)
// stream handling.

globalThis.AssistantStreaming = (function() {
  return {
    async sendMessage(tags) {
      if (!this.newMessage.trim()) return;

      if (!this.canChat) return;
      
      if (!this.assistantEnabled) {
        this.$root.showError(this.i18n.assistantNotAvailable);
        return;
      }

      const isCompressing = tags && tags.includes(MSGTAG_CONTEXTCOMPRESSION);
      if (!isCompressing && this.isMessageTooLong) return;
      if (!isCompressing && this.checkContextLimitReached()) return;
      
      // Bail out if the model wasn't reachable when credits were last fetched
      if (!this.creditsLoaded) {
        this.$root.showError(this.i18n.assistantBalanceCheckUnhealthy);
        return;
      }

      if (this.creditsRemaining <= 0) {
        this.$root.showError(this.i18n.assistantOutOfCredits);
        return;
      }
      
      // Generate the session ID before the API call so a later URL update can't interrupt tool execution.
      if (!this.currentChatId) {
        this.currentChatId = this.generateChatId();
        this.saveCurrentChatId();
      }
      
      if (this.currentChatId && !this.$route.params.sessionId) {
        await this.updateUrlWithSessionId(this.currentChatId);
        await this.$nextTick();
      }
      
      const userMessage = {
        role: 'user',
        content: this.newMessage.trim(),
        timestamp: new Date().toISOString()
      };
      
      if (this.messages.length == 1) {
        this.messages = [];
      }

      const floatingState = this.sessionToolState.get(this.currentChatId);
      if (this.messages.length > 1 && floatingState && floatingState.floatingTool) {
        floatingState.floatingTool.status = 'skipped';
        floatingState.floatingTool = null;
      }

      this.messages.push(userMessage);
      const messageText = this.newMessage.trim();
      this.newMessage = '';
      this.scrollToBottom();
      
      this.isTyping = true;
      
      await this.callAIAPI(messageText, tags);

      await this.loadStoredChats(false);
    },
    
    // Parse a JSON chunk, splitting concatenated objects and flagging any trailing partial.
    parseJsonChunk(chunk) {
      try {
        return { success: true, data: JSON.parse(chunk), isPartial: null };
      } catch {
        // Handle partial JSON or multiple concatenated JSON objects
        const splitChunks = [];
        let currentChunk = '';
        let braceCount = 0;
        let inString = false;
        let escaped = false;
        
        for (let j = 0; j < chunk.length; j++) {
          const char = chunk[j];
          currentChunk += char;
          
          if (escaped) {
            escaped = false;
            continue;
          }
          
          if (char === '\\') {
            escaped = true;
            continue;
          }
          
          if (char === '"') {
            inString = !inString;
            continue;
          }
          
          if (!inString) {
            if (char === '{') {
              braceCount++;
            } else if (char === '}') {
              braceCount--;
              if (braceCount === 0) {
                splitChunks.push(currentChunk);
                currentChunk = '';
              }
            }
          }
        }
        
        if (splitChunks.length > 0) {
          return {
            success: true,
            data: splitChunks,
            isPartial: currentChunk.trim() ? currentChunk : null
          };
        } else if (currentChunk.trim()) {
          return { success: false, data: null, isPartial: currentChunk };
        } else {
          return { success: false, data: null, isPartial: chunk };
        }
      }
    },
    
    processStreamingChunks(value, chunks, partial) {
      // Cleanup the data, split messages apart, remove SSE label, filter out empty lines
      const newChunks = value.split('\n\n').filter(d => d.trim()).map(d => (d.startsWith("data: ") ? d.slice(6) : d));
      
      // If the last read had partial data, prepend it to the new data and process it again
      if (partial) {
        newChunks[0] = chunks[0] + newChunks[0];
        partial = false;
      }
      
      return { chunks: newChunks, partial };
    },
    
    handleMessageStart(c, assistantMessage) {
      this.isTyping = false;

      const msg = {
        role: 'assistant',
        thoughts: '',
        content: '',
        timestamp: new Date().toISOString(),
        usage: null,
        toolUses: [] // Track tool uses in this message
      };

      // Sometimes usage comes in message_start
      let messageUsage = null;
      if (c.message && c.message.usage) {
        messageUsage = c.message.usage;
      }

      this.messages.push(msg);
      // Mutate the reactive instance now living in this.messages so streaming
      // updates (content/thoughts/toolUses) notify the template.
      assistantMessage = this.messages[this.messages.length - 1];
      this.scrollIfPinned();

      return { assistantMessage, messageUsage };
    },
    
    // --- Unified content-block stream handlers ---
    // One implementation for all three streaming contexts (orchestrator turn, chained
    // tool-result turn, delegated sub-agent); differences ride in `target`: message
    // (null = don't render), sessionId (owns the tool maps), visible (scroll-if-pinned).
    // handle*ContentBlock* are thin adapters that build `target`; apply* do the work.
    applyBlockStart(c, target) {
      if (!(c.content_block && c.content_block.type === 'tool_use')) return;
      const toolUse = {
        id: c.content_block.id,
        name: c.content_block.name,
        input: c.content_block.input || {},
        inputJson: '', // Accumulate input JSON from deltas
        status: 'preparing', // Start as preparing, not executing
        result: null,
        error: null,
        rawResult: null, // Will store the raw tool result
        timestamp: new Date().toISOString(),
        blockIndex: c.index, // Store the block index for tracking
        approved: null, // null = pending, true = approved, false = rejected
        sessionId: target.sessionId, // Track which session this belongs to
      };

      // Push into the reactive message first, then track that reactive instance in the
      // session map so later mutations (status, input, childSession) notify the view.
      let tracked = toolUse;
      if (target.message) {
        target.message.toolUses.push(toolUse);
        tracked = target.message.toolUses[target.message.toolUses.length - 1];
        if (target.visible) this.scrollIfPinned();
      }
      this.getSessionToolMap(target.sessionId).set(toolUse.id, tracked);
      this.getIndexMap(target.sessionId).set(c.index, toolUse.id);
    },
    applyBlockDelta(c, target) {
      if (c.delta.type === 'text_delta') {
        if (target.message) {
          target.message.content = this.nbspRegexOp(target.message.content + c.delta.text);
          if (target.visible) this.scrollIfPinned();
        }
      } else if (c.delta.type === 'input_json_delta') {
        const toolId = this.getIndexMap(target.sessionId).get(c.index);
        const toolUse = this.getSessionToolMap(target.sessionId).get(toolId);
        if (toolUse) {
          toolUse.inputJson += c.delta.partial_json;
          toolUse.status = 'preparing';
          if (target.visible) this.scrollIfPinned();
        }
      } else if (c.delta.type === 'thought_delta') {
        if (target.message) {
          target.message.thoughts += this.nbspRegexOp(c.delta.text);
          if (target.visible) this.scrollIfPinned();
        }
      }
    },
    applyBlockStop(c, target) {
      let messageUsage = null;
      const toolId = this.getIndexMap(target.sessionId).get(c.index);
      const toolUse = this.getSessionToolMap(target.sessionId).get(toolId);
      if (toolUse && toolUse.status === 'preparing') {
        try {
          if (toolUse.inputJson) {
            toolUse.input = JSON.parse(toolUse.inputJson);
          }
          // Read-only tools honor the auto-approval setting; everything else prompts.
          if (this.shouldAutoApproveTool(toolUse.name)) {
            if (this.checkContextLimitReached()) return messageUsage;
            toolUse.approved = true;
            this.queueTool(target.sessionId, toolUse.id);
          } else {
            toolUse.status = 'pending_approval';
            toolUse.approved = null;
            this.sessionTools(target.sessionId).floatingTool = toolUse;
          }
        } catch (error) {
          toolUse.status = 'error';
          toolUse.error = this.i18n.assistantToolParseInputError + ': ' + error.message;
        }
        if (target.visible) this.scrollIfPinned();
      }
      // Usage sometimes rides the content_block_stop event.
      if (c.usage) {
        messageUsage = c.usage;
      }
      return messageUsage;
    },

    // Adapter: the orchestrator's own turn renders into the current session's message.
    handleContentBlockStart(c, assistantMessage, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      this.applyBlockStart(c, { message: assistantMessage, sessionId: sid, visible: sid === this.currentChatId });
    },
    handleContentBlockDelta(c, assistantMessage, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      this.applyBlockDelta(c, { message: assistantMessage, sessionId: sid, visible: sid === this.currentChatId });
    },
    handleContentBlockStop(c, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      return this.applyBlockStop(c, { sessionId: sid, visible: sid === this.currentChatId });
    },
    
    handleMessageStop(assistantMessage, messageUsage) {
      if (assistantMessage && messageUsage) {
        assistantMessage.usage = messageUsage;
        this.updateContextLength(messageUsage);
        // This only runs for the current session, so currentModel is its producing agent.
        this.accrueCredits(messageUsage, this.currentModel);
        this.$forceUpdate();
      }
      
      return { assistantMessage: null, messageUsage: null };
    },
    
    async callAIAPI(userMessage, tags = null) {
      const streamingSessionId = this.currentChatId;
      this.activeStreamingSessionId = streamingSessionId;
      let reader = null;

      try {
        let url = '/assistant/chat';
        const socId = this.$route.query.socId;
        if (socId) {
          url += `?entityType=alert_investigation&entityId=${encodeURIComponent(socId)}`;
          // Clear the investigation query params after first use to prevent
          // marking the alert as investigated on every subsequent message
          this.$nextTick(() => {
            const query = { ...this.$route.query };
            delete query.investigation;
            delete query.socId;
            this.$router.replace({
              name: 'assistant',
              params: this.$route.params,
              query: query
            });
          });
        }
        
        const response = await this.$root.papi.post(url, {
          msg: userMessage,
          sessionId: streamingSessionId,
          model: this.currentModel,
          tags: tags,
        },
        {
          headers: {
            'Accept': 'text/event-stream'
          },
          responseType: 'stream',
          adapter: 'fetch',
        });

        const stream = response.data;
        reader = stream.pipeThrough(new TextDecoderStream()).getReader();

        this.isStreaming = true;
        let output = 0;
        let assistantMessage = null;
        let chunks = [];
        let partial = false;
        let messageUsage = null;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          // Check if we're still in the same session for UI updates
          const isCurrentSession = this.activeStreamingSessionId === streamingSessionId && this.currentChatId === streamingSessionId;
          
          const chunkResult = this.processStreamingChunks(value, chunks, partial);
          chunks = chunkResult.chunks;
          partial = chunkResult.partial;
          
          for (let i = 0; i < chunks.length; i++) {
            if (chunks[i] === '[DONE]') {
              assistantMessage = null;
              continue;
            }

            const parseResult = this.parseJsonChunk(chunks[i]);
            
            if (!parseResult.success) {
              if (parseResult.isPartial) {
                partial = true;
                chunks = [parseResult.isPartial];
                break;
              }
              continue;
            }
            
            if (Array.isArray(parseResult.data)) {
              chunks.splice(i, 1, ...parseResult.data);
              i--; // Reprocess from current position
              
              if (parseResult.isPartial) {
                partial = true;
                chunks.push(parseResult.isPartial);
              }
              continue;
            }

            const c = parseResult.data;

            // Always process chunks for tool execution logic, but only update UI if current session
            switch (c.type) {
              case 'message_start':
                if (isCurrentSession) {
                  const startResult = this.handleMessageStart(c, assistantMessage);
                  assistantMessage = startResult.assistantMessage;
                  if (startResult.messageUsage) {
                    messageUsage = startResult.messageUsage;
                  }
                }
                break;
                
              case 'content_block_start':
                this.handleContentBlockStart(c, isCurrentSession ? assistantMessage : null, streamingSessionId);
                break;
                
              case 'content_block_delta':
                this.handleContentBlockDelta(c, isCurrentSession ? assistantMessage : null, streamingSessionId);
                break;
                
              case 'content_block_stop':
                const stopUsage = this.handleContentBlockStop(c, streamingSessionId);
                if (stopUsage && isCurrentSession) {
                  messageUsage = stopUsage;
                }
                break;
                
              case 'message_stop':
                if (isCurrentSession) {
                  const stopResult = this.handleMessageStop(assistantMessage, messageUsage);
                  assistantMessage = stopResult.assistantMessage;
                  messageUsage = stopResult.messageUsage;
                }
                break;
                
              case 'message_delta':
                if (c.usage && isCurrentSession) {
                  messageUsage = c.usage;
                }
                break;
                
              default:
                // Unhandled event types may still carry usage.
                if (c.usage && isCurrentSession) {
                  messageUsage = c.usage;
                }
                break;
            }
          }

          if (isCurrentSession) {
            await this.$nextTick();
          }
          output++;
        }
        
        if (this.activeStreamingSessionId === streamingSessionId && this.currentChatId === streamingSessionId) {
          this.isStreaming = false;
          // Update credits from API after successful response
          await this.loadCredits();
        }
        
        if (this.activeStreamingSessionId === streamingSessionId) {
          this.activeStreamingSessionId = null;
        }
        
      } catch (error) {
        if (this.activeStreamingSessionId === streamingSessionId && this.currentChatId === streamingSessionId) {
          this.isTyping = false;
          this.isStreaming = false;
          
          const errorMessage = {
            role: 'assistant',
            content: this.i18n.assistantErrorMessage,
            timestamp: new Date().toISOString()
          };
          this.messages.push(errorMessage);
          this.scrollIfPinned();

          if (error && error.response && error.response.data) {
            const stream = error.response.data;
            const errorReader = stream.pipeThrough(new TextDecoderStream()).getReader();
            const { done, value } = await errorReader.read();
            error = value;
          }

          this.$root.showError(error);
        }
        
        if (this.activeStreamingSessionId === streamingSessionId) {
          this.activeStreamingSessionId = null;
        }
      } finally {
        // Release the stream reader so an interrupted turn (mid-stream error or
        // session switch) can't leak the underlying connection.
        if (reader) {
          try {
            await reader.cancel();
          } catch (e) {
            // already closed; nothing to release
          }
        }
      }
    },

    handleToolExecutionMessageStart(c, assistantMessage, toolUse) {
      const msg = {
        role: 'assistant',
        thoughts: '',
        content: '',
        timestamp: new Date().toISOString(),
        usage: null,
        toolUses: [], // Track tool uses in this response too
        isToolResult: true,
        toolName: toolUse.name,
        toolId: toolUse.id
      };

      let messageUsage = null;
      if (c.message && c.message.usage) {
        messageUsage = c.message.usage;
      }

      this.messages.push(msg);
      // Mutate the reactive instance from this.messages so streaming notifies.
      assistantMessage = this.messages[this.messages.length - 1];
      this.scrollIfPinned();

      return { assistantMessage, messageUsage };
    },
    
    // Adapter: a chained tool-result turn renders the same way as the orchestrator's
    // own turn, so it reuses the unified content-block handlers verbatim.
    handleToolExecutionContentBlockStart(c, assistantMessage, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      this.applyBlockStart(c, { message: assistantMessage, sessionId: sid, visible: sid === this.currentChatId });
    },
    handleToolExecutionContentBlockDelta(c, assistantMessage, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      this.applyBlockDelta(c, { message: assistantMessage, sessionId: sid, visible: sid === this.currentChatId });
    },
    handleToolExecutionContentBlockStop(c, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      return this.applyBlockStop(c, { sessionId: sid, visible: sid === this.currentChatId });
    },

    // --- Delegation (sub-agent) streaming helpers ---
    // A sub-agent runs as its own session but renders nested under the parent's delegate
    // tool block (toolUse.childSession); its tool requests prompt like top-level tools,
    // routed by the child session id.

    // Lazily create the nested render container on a delegate tool block. delegateToolUse
    // must be the reactive instance from this.messages so attaching childSession notifies the template.
    ensureChildSession(delegateToolUse, agentName) {
      if (!delegateToolUse.childSession) {
        delegateToolUse.childSession = {
          agentName: agentName || '',
          messages: [],
        };
      } else if (agentName) {
        delegateToolUse.childSession.agentName = agentName;
      }
      return delegateToolUse.childSession;
    },

    // Child tools awaiting approval, surfaced OUTSIDE the collapsed sub-agent region so they
    // stay actionable; once answered they fold back into the collapsed transcript.
    pendingChildTools(delegateToolUse) {
      const cs = delegateToolUse && delegateToolUse.childSession;
      if (!cs || !Array.isArray(cs.messages)) return [];
      const pending = [];
      for (const m of cs.messages) {
        const tools = m && m.toolUses;
        if (!Array.isArray(tools)) continue;
        for (const t of tools) {
          if (t.status === 'pending_approval') pending.push(t);
        }
      }
      return pending;
    },

    // Credits this delegate's own turns cost. Grandchild delegations live in their own
    // nested cards, so summing only this session's messages excludes them (leaf cost).
    delegateOwnCredits(delegateToolUse) {
      const cs = delegateToolUse && delegateToolUse.childSession;
      if (!cs || !Array.isArray(cs.messages)) return 0;
      return cs.messages.reduce((sum, m) => sum + ((m.usage && m.usage.credits) || 0), 0);
    },

    // Output tokens this delegate's own turns generated — the number its per-sub-session
    // output-token budget constrains. Leaf-scoped like delegateOwnCredits.
    delegateOwnOutputTokens(delegateToolUse) {
      const cs = delegateToolUse && delegateToolUse.childSession;
      if (!cs || !Array.isArray(cs.messages)) return 0;
      return cs.messages.reduce((sum, m) => sum + ((m.usage && m.usage.output_tokens) || 0), 0);
    },

    // Whether the collapsed sub-agent region has anything worth showing — avoids an empty
    // expandable when the only activity so far is a still-pending tool shown outside.
    delegationHasCollapsedContent(delegateToolUse) {
      const cs = delegateToolUse && delegateToolUse.childSession;
      if (!cs || !Array.isArray(cs.messages)) return false;
      for (const m of cs.messages) {
        if (m && m.content) return true;
        if (m && m.thoughts) return true;
        const tools = m && m.toolUses;
        if (Array.isArray(tools) && tools.some(t => t.status !== 'pending_approval')) return true;
      }
      return false;
    },

    // message_start within a delegated sub-agent's stream: begin a new nested message.
    handleDelegationMessageStart(delegateToolUse) {
      const childMsg = {
        role: 'assistant',
        thoughts: '',
        content: '',
        toolUses: [],
        timestamp: new Date().toISOString(),
      };
      delegateToolUse.childSession.messages.push(childMsg);
      this.scrollIfPinned();
      // Return the reactive instance now in childSession.messages so streaming
      // updates to this nested message notify the template.
      return delegateToolUse.childSession.messages[delegateToolUse.childSession.messages.length - 1];
    },

    // Adapter: a delegated sub-agent's turn renders into its nested childMsg, always on
    // screen, so visible is always true; tool approvals route back to the child session id.
    handleDelegationContentBlockStart(c, childSessionId, childMsg) {
      this.applyBlockStart(c, { message: childMsg, sessionId: childSessionId, visible: true });
    },
    handleDelegationContentBlockDelta(c, childSessionId, childMsg) {
      this.applyBlockDelta(c, { message: childMsg, sessionId: childSessionId, visible: true });
    },
    handleDelegationContentBlockStop(c, childSessionId) {
      this.applyBlockStop(c, { sessionId: childSessionId, visible: true });
    },

    // Attach a tool's result to its card and advance status to completed/error. The result
    // arrives inline via the backend's synthetic tool_result SSE event (see executeTool), so
    // no session re-fetch is needed. Empty content still advances status, else the card spins forever.
    applyStreamedToolResult(toolUse, toolResult) {
      toolUse.completedAt = new Date().toISOString();
      // A declined tool reports a 'rejected' result; keep the rejected card (not error).
      if (toolResult.status === 'rejected') {
        toolUse.status = 'rejected';
        toolUse.error = toolResult.content?.[0]?.text || this.i18n.assistantToolUseReject;
        return;
      }
      if (toolResult.isError || toolResult.status === 'error') {
        toolUse.rawResult = null;
        toolUse.error = toolResult.content?.[0]?.text || this.i18n.assistantToolUnknownError;
        toolUse.status = 'error';
      } else {
        toolUse.rawResult = toolResult.content?.[0]?.json ?? null;
        toolUse.status = 'completed';
      }
    },
  };
})();
