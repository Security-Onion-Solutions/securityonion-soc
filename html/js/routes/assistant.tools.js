// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Assistant page methods: tool request posting, execution, approval/rejection,
// tool status display, and the per-session tool-queue state (see sessionTools).

globalThis.AssistantTools = (function() {
  return {
    // postToolRequest POSTs a tool result and streams the assistant's continuation.
    // On a 409 (another tool turn is already running for this session; the backend
    // fails fast instead of blocking) it waits and retries, up to a bounded number of
    // attempts, then re-throws so the caller surfaces the error.
    async postToolRequest(toolUse, toolRequest) {
      for (let attempt = 0; ; attempt++) {
        try {
          return await this.$root.papi.post(`/assistant/tool/${toolUse.name}`, toolRequest, {
            headers: { 'Accept': 'text/event-stream' },
            responseType: 'stream',
            adapter: 'fetch',
          });
        } catch (error) {
          if (error.response && error.response.status === 409 && attempt < this.toolBusyMaxRetries) {
            await new Promise(resolve => setTimeout(resolve, this.toolBusyRetryDelayMs));
            continue;
          }
          throw error;
        }
      }
    },
    async executeTool(toolUse) {
      // Use the tool's session ID if available, otherwise use current session
      let toolStreamingSessionId = toolUse.sessionId || this.currentChatId;

      let childMsg = null;
      let reader = null;

      try {
        // Create ToolRequest object with history and params. A rejected tool is not
        // executed: the backend records an error tool_result so the turn resolves.
        const rejected = toolUse.approved === false;
        const toolRequest = {
          sessionId: toolStreamingSessionId,
          toolUseId: toolUse.id,
          params: toolUse.input,
          model: this.currentModel,
          rejected,
        };

        if (!rejected) this.applyToolSpecificChanges(toolUse, toolRequest);

        // Use streaming for tool results. A 409 means another tool turn is already
        // running for this session (the backend fails fast instead of blocking, so a
        // long tool response can't hold this request open or leave a saved result
        // orphaned by a cancelled request). Wait briefly and retry rather than erroring.
        const response = await this.postToolRequest(toolUse, toolRequest);

        // Update tool status to executing only if visible in the current session. A
        // rejected tool was never executing; keep its 'rejected' status.
        if (!rejected && this.currentChatId === toolStreamingSessionId) {
          toolUse.status = 'executing';
        }

        // Stream the AI's response to the tool result
        const stream = response.data;
        reader = stream.pipeThrough(new TextDecoderStream()).getReader();

        if (this.currentChatId === toolStreamingSessionId || this.delegationChildren.has(toolStreamingSessionId)) {
          this.isStreaming = true;
        }
        let assistantMessage = null;
        let chunks = [];
        let partial = false;
        let messageUsage = null;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          // Process streaming chunks using helper method
          const chunkResult = this.processStreamingChunks(value, chunks, partial);
          chunks = chunkResult.chunks;
          partial = chunkResult.partial;

          for (let i = 0; i < chunks.length; i++) {
            if (chunks[i] === '[DONE]') {
              assistantMessage = null;
              continue;
            }

            // Parse JSON chunk using helper method
            const parseResult = this.parseJsonChunk(chunks[i]);

            if (!parseResult.success) {
              // Handle partial JSON
              if (parseResult.isPartial) {
                partial = true;
                chunks = [parseResult.isPartial];
                break;
              }
              continue;
            }

            // Handle multiple JSON objects in one chunk
            if (Array.isArray(parseResult.data)) {
              chunks.splice(i, 1, ...parseResult.data);
              i--; // Reprocess from current position

              // If there's remaining partial content, save it for next read
              if (parseResult.isPartial) {
                partial = true;
                chunks.push(parseResult.isPartial);
              }
              continue;
            }

            const c = parseResult.data;
            const isCurrentSession = this.currentChatId === toolStreamingSessionId;

            // The executed tool's result arrives inline as a synthetic tool_result
            // event; attach it to the tool card here rather than re-fetching the
            // session. Only direct execution emits it (delegations resolve via the
            // markers below), and it always targets this stream's tool.
            if (c.type === 'tool_result') {
              if (c.toolResult && c.toolResult.toolUseId === toolUse.id) {
                this.applyStreamedToolResult(toolUse, c.toolResult);
              }
              continue;
            }

            // Delegation markers retarget the stream between the sub-agent's nested
            // session and the parent thread (the backend chains both onto one response).
            if (c.type === 'delegation_start') {
              // A delegation_start is only ever emitted in the stream executing that
              // delegate tool, so the owner is this stream's tool.
              const owner = toolUse;
              this.delegationChildren.set(c.childSessionId, {
                parentToolUse: owner,
                parentSessionId: owner.sessionId,
                parentToolUseId: c.parentToolUseId,
                agentName: c.agentName,
              });
              this.ensureChildSession(owner, c.agentName);
              toolStreamingSessionId = c.childSessionId;
              childMsg = null;
              continue;
            }
            if (c.type === 'delegation_resolved') {
              // Close the boundary: mark the delegate tool done and forget the child
              // session so nothing that streams afterward (the resumed parent turn)
              // can be misattributed back under this delegate.
              const resolvedChild = this.delegationChildren.get(toolStreamingSessionId);
              const owner = resolvedChild && resolvedChild.parentToolUse;
              if (owner) {
                owner.status = 'completed';
                owner.completedAt = new Date().toISOString();
              }
              if (this.delegationChildren.has(toolStreamingSessionId)) {
                this.delegationChildren.delete(toolStreamingSessionId);
                this.sessionToolState.delete(toolStreamingSessionId);
              }
              childMsg = null;
              assistantMessage = null;
              toolStreamingSessionId = c.parentSessionId;
              continue;
            }

            // Decide nesting purely from the delegationChildren map. A chunk renders
            // nested under the delegate tool only while its session id is still a live
            // child entry. delegation_resolved (above) deletes that entry, so the
            // parent's resumed turn falls through to top-level rendering automatically.
            const activeChild = this.delegationChildren.get(toolStreamingSessionId);
            if (activeChild) {
              const owner = activeChild.parentToolUse;
              switch (c.type) {
                case 'error':
                  this.$root.showError(this.i18n.assistantToolUseFail + ': ' + c.error.message);
                  break;
                case 'message_start':
                  childMsg = this.handleDelegationMessageStart(owner);
                  break;
                case 'content_block_start':
                  this.handleDelegationContentBlockStart(c, toolStreamingSessionId, childMsg);
                  break;
                case 'content_block_delta':
                  this.handleDelegationContentBlockDelta(c, toolStreamingSessionId, childMsg);
                  break;
                case 'content_block_stop':
                  this.handleDelegationContentBlockStop(c, toolStreamingSessionId);
                  break;
                default:
                  break;
              }
              continue;
            }

            // Normal (parent / top-level) tool result rendering.
            switch (c.type) {
              case 'error':
                this.$root.showError(this.i18n.assistantToolUseFail + ': ' + c.error.message);
                break;
              case 'message_start':
                if (isCurrentSession) {
                  const startResult = this.handleToolExecutionMessageStart(c, assistantMessage, toolUse);
                  assistantMessage = startResult.assistantMessage;
                  if (startResult.messageUsage) {
                    messageUsage = startResult.messageUsage;
                  }
                }
                break;

              case 'content_block_start':
                this.handleToolExecutionContentBlockStart(c, isCurrentSession ? assistantMessage : null, toolStreamingSessionId);
                break;

              case 'content_block_delta':
                this.handleToolExecutionContentBlockDelta(c, isCurrentSession ? assistantMessage : null, toolStreamingSessionId);
                break;

              case 'content_block_stop':
                const stopUsage = this.handleToolExecutionContentBlockStop(c, toolStreamingSessionId);
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
                if (c.usage && isCurrentSession) {
                  messageUsage = c.usage;
                }
                break;
            }
          }

          await this.$nextTick();
        }

        this.isStreaming = false;
        // Update credits if the turn that finished is the one in view
        if (this.currentChatId === toolStreamingSessionId) {
          await this.loadCredits();
        }
      } catch (error) {
        // Always update tool status with error, but only update UI if current session
        toolUse.status = 'error';
        toolUse.error = error.message;
        this.isStreaming = false;

        // If a delegation was still in flight (its session has a live child entry),
        // the delegate card and child session are still open. Close them here so a
        // dropped/aborted stream can't leave the delegate tool spinning forever (the
        // backend may not have emitted a delegation_resolved marker). Derived from
        // the map before the cleanup below deletes the entry.
        const activeDelegate = this.delegationChildren.get(toolStreamingSessionId)?.parentToolUse;
        if (activeDelegate) {
          activeDelegate.status = 'error';
          activeDelegate.error = error.message;
          activeDelegate.completedAt = new Date().toISOString();
        }
        if (this.delegationChildren.has(toolStreamingSessionId)) {
          this.delegationChildren.delete(toolStreamingSessionId);
          this.sessionToolState.delete(toolStreamingSessionId);
        }

        const isCurrentSession = this.currentChatId === (toolUse.sessionId || this.currentChatId);

        if (isCurrentSession && !activeDelegate) {
          // Add error message to chat
          const errorMessage = {
            role: 'assistant',
            content: `Error executing tool "${toolUse.name}": ${error.message}`,
            timestamp: new Date().toISOString(),
            isToolResult: true,
            toolName: toolUse.name,
            toolId: toolUse.id
          };

          this.messages.push(errorMessage);
          this.scrollIfPinned();
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
    // displayStatus is the status to render for a tool, which can differ from its raw
    // status. A delegate stays 'executing' while its sub-agent is parked on a tool
    // awaiting the user's approval (it must remain non-approvable so re-prompting can't
    // spawn a duplicate sub-session), but it isn't actually working -- surface
    // 'action_needed' so the card shows a "needs you" indicator, not a busy spinner.
    displayStatus(toolUse) {
      if (toolUse.status === 'executing' && this.hasPendingDescendantApproval(toolUse)) {
        return 'action_needed';
      }
      return toolUse.status;
    },
    // Whether any tool nested under this delegate (at any depth) is awaiting approval.
    hasPendingDescendantApproval(toolUse) {
      const cs = toolUse && toolUse.childSession;
      if (!cs || !Array.isArray(cs.messages)) return false;
      for (const m of cs.messages) {
        if (!m || !Array.isArray(m.toolUses)) continue;
        for (const t of m.toolUses) {
          if (t.status === 'pending_approval') return true;
          if (this.hasPendingDescendantApproval(t)) return true;
        }
      }
      return false;
    },
    getToolStatusIcon(status) {
      switch (status) {
        case 'preparing': return 'fa-cog';
        case 'queued': return 'fa-cog';
        case 'skipped': return 'fa-circle-info';
        case 'pending_approval': return 'fa-question-circle';
        case 'action_needed': return 'fa-user-clock';
        case 'executing': return 'fa-hourglass-half';
        case 'completed': return 'fa-check-circle';
        case 'error': return 'fa-exclamation-triangle';
        case 'rejected': return 'fa-times-circle';
        default: return 'fa-question-circle';
      }
    },
    getToolStatusColor(status) {
      switch (status) {
        case 'preparing': return 'info';
        case 'queued': return 'info';
        case 'skipped': return 'info';
        case 'pending_approval': return 'warning';
        case 'action_needed': return 'warning';
        case 'executing': return 'warning';
        case 'completed': return 'success';
        case 'error': return 'error';
        case 'rejected': return 'error';
        default: return 'info';
      }
    },
    getToolStatusTitle(status) {
      switch (status) {
        case 'preparing': return this.i18n.preparing;
        case 'queued': return this.i18n.preparing;
        case 'skipped': return this.i18n.skipped;
        case 'pending_approval': return this.i18n.pendingApproval;
        case 'action_needed': return this.i18n.actionNeeded;
        case 'executing': return this.i18n.executing;
        case 'completed': return this.i18n.completed;
        case 'error': return this.i18n.error;
        case 'rejected': return this.i18n.rejected;
        default: return this.i18n.statusUnknown;
      }
    },
    // A tool is top-level when it belongs to the viewed conversation rather than a
    // nested sub-agent session; only those should drive the main view's scroll.
    isTopLevelTool(toolUse) {
      return !toolUse.sessionId || toolUse.sessionId === this.currentChatId;
    },
    async approveTool(toolUse) {
      try {
        if (this.checkContextLimitReached()) return;
        toolUse.approved = true;
        toolUse.status = 'preparing';
        this.clearFloatingTool(toolUse.sessionId || this.currentChatId);
        this.queueTool(toolUse.sessionId || this.currentChatId, toolUse.id);
      } catch (error) {
        toolUse.status = 'error';
        toolUse.error = this.i18n.assistantToolUseFail + ': ' + error.message;
      }
      if (this.isTopLevelTool(toolUse)) this.scrollToBottom();
    },
    async rejectTool(toolUse) {
      if (this.checkContextLimitReached()) return;
      toolUse.approved = false;
      toolUse.status = 'rejected';
      toolUse.error = this.i18n.assistantToolUseReject;
      this.clearFloatingTool(toolUse.sessionId || this.currentChatId);

      // Submit the rejection as a tool_result (the backend records an error result and
      // resumes the turn). Routing it through the same queue as approvals keeps a
      // parallel turn's tools serialized, so its coalescing resolves correctly.
      this.queueTool(toolUse.sessionId || this.currentChatId, toolUse.id);
      if (this.isTopLevelTool(toolUse)) this.scrollToBottom();
    },
    applyToolSpecificChanges(toolUse, toolRequest) {
      if (toolUse.name === 'query_cases') {
        const rawMRU = localStorage.getItem('settings.case.mruCases');
        if (rawMRU) {
          const cases = JSON.parse(rawMRU);
          toolRequest.auxData = cases;
        }
      }
    },
    // sessionTools returns the per-session tool-execution state, creating it on first
    // use. One record consolidates the tools-by-id map, the stream block-index ->
    // tool-id map, the approval queue, the runner-busy flag, and the floating
    // (pending-approval) tool shown above a collapsed delegate.
    sessionTools(sessionId) {
      let s = this.sessionToolState.get(sessionId);
      if (!s) {
        s = { toolsById: new Map(), indexToId: new Map(), queue: [], busy: false, floatingTool: null };
        this.sessionToolState.set(sessionId, s);
      }
      return s;
    },
    getSessionToolMap(sessionId) {
      return this.sessionTools(sessionId).toolsById;
    },
    getIndexMap(sessionId) {
      return this.sessionTools(sessionId).indexToId;
    },
    // clearFloatingTool drops the pending-approval tool a session was surfacing above
    // its collapsed delegate, without disturbing the rest of that session's state.
    clearFloatingTool(sessionId) {
      const s = this.sessionToolState.get(sessionId);
      if (s) s.floatingTool = null;
    },
    queueTool(sessionId, toolUseId) {
      this.sessionTools(sessionId).queue.push(toolUseId);
      this.runToolQueue(sessionId);
    },
    async runToolQueue(sessionId) {
      const s = this.sessionTools(sessionId);
      if (s.busy) return;
      s.busy = true;
      try {
        // Re-read the record each iteration: a session's state can be torn down
        // mid-run (e.g. a resolved delegation), which ends the loop just as the old
        // per-session map deletes did.
        while (true) {
          const cur = this.sessionToolState.get(sessionId);
          if (!cur || cur.queue.length === 0) break;
          const toolUseId = cur.queue[0];
          const toolUse = cur.toolsById.get(toolUseId);
          // A rejected tool (approved === false) still needs its declination submitted
          // to the backend, so it bypasses the resolved skip-list; everything else that
          // is already terminal is dropped.
          const isReject = toolUse && toolUse.approved === false;
          if (!toolUse || (!isReject && ['completed','error','rejected'].includes(toolUse.status))) {
            cur.queue.shift();
            continue;
          }
          // executeTool keeps a reject's 'rejected' status; only an approved tool runs.
          if (!isReject) toolUse.status = 'executing';
          await this.executeTool(toolUse);
          cur.queue.shift();
        }
      } finally {
        const cur = this.sessionToolState.get(sessionId);
        if (cur) cur.busy = false;
      }
    },
    checkForActivity() {
      if (this.isStreaming || this.isTyping) return true;
      // Tool queues are per session: a delegation runs its sub-agent's tools under the
      // child session, not the current one. Count queued work in the current session or
      // any live delegation child (tracked in delegationChildren) as activity, so the
      // send/export controls stay disabled while a sub-agent's tools are still running.
      const queued = (sessionId) => {
        const s = this.sessionToolState.get(sessionId);
        return !!(s && s.queue.length > 0);
      };
      if (queued(this.currentChatId)) return true;
      for (const childSessionId of this.delegationChildren.keys()) {
        if (queued(childSessionId)) return true;
      }
      return false;
    },
    async compressCurrentSession() {
      const oldMsg = this.newMessage;
      this.newMessage = this.compressContextMsg;

      this.contextLength = 0;
      
      await this.sendMessage([MSGTAG_CONTEXTCOMPRESSION]);
      this.loadChatFromBackend(this.currentChatId);
      
      if (oldMsg) this.newMessage = oldMsg;
    },
  };
})();
