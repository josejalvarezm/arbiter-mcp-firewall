//! Task executor — connects engine routing decisions to a real LLM.

use crate::client::{ChatCompletion, LlmClient};
use crate::RuntimeResult;
use arbiter_shared::contract::AgentContract;
use arbiter_shared::task::{Task, TaskResult, TaskStatus};
use chrono::Utc;
use tracing::instrument;

/// The result of an agent execution, including LLM metadata.
#[derive(Debug)]
pub struct ExecutionResult {
    pub task_result: TaskResult,
    pub completion: ChatCompletion,
}

/// Execute a task by sending it to the LLM, using the agent's contract as context.
///
/// The caller is responsible for:
/// 1. Running policy enforcement (engine.evaluate())
/// 2. Passing only ALLOWED tasks to this function
/// 3. Recording the outcome
#[instrument(skip(client, agent, task), fields(agent_id = %agent.id, task_id = %task.id))]
pub async fn execute_task(
    client: &LlmClient,
    agent: &AgentContract,
    task: &Task,
) -> RuntimeResult<ExecutionResult> {
    let system_prompt = build_system_prompt(agent);
    let user_message = build_user_message(task);

    let completion = client.chat(&system_prompt, &user_message).await?;

    let task_result = TaskResult {
        task_id: task.id.clone(),
        agent_id: agent.id.clone(),
        status: TaskStatus::Success,
        output: Some(completion.content.clone()),
        errors: vec![],
        completed_at: Utc::now(),
    };

    Ok(ExecutionResult {
        task_result,
        completion,
    })
}

fn build_system_prompt(agent: &AgentContract) -> String {
    let mut prompt = format!(
        "You are agent '{}'. Follow these rules strictly:\n\n",
        agent.id
    );

    if !agent.rules.is_empty() {
        prompt.push_str("## Rules\n");
        for rule in &agent.rules {
            prompt.push_str(&format!("- {rule}\n"));
        }
        prompt.push('\n');
    }

    if !agent.constraints.is_empty() {
        prompt.push_str("## Constraints\n");
        for constraint in &agent.constraints {
            prompt.push_str(&format!("- {constraint}\n"));
        }
        prompt.push('\n');
    }

    if !agent.capabilities.is_empty() {
        prompt.push_str("## Your Capabilities\n");
        for cap in &agent.capabilities {
            prompt.push_str(&format!("- {cap}\n"));
        }
        prompt.push('\n');
    }

    prompt.push_str(
        "Respond only within your declared capabilities. \
         If a task falls outside your scope, say so explicitly.\n",
    );

    prompt
}

fn build_user_message(task: &Task) -> String {
    let payload_str = if task.payload.is_null() {
        String::new()
    } else {
        format!(
            "\n\nContext:\n{}",
            serde_json::to_string_pretty(&task.payload).unwrap_or_default()
        )
    };

    format!("Task: {}\nType: {}{}", task.id, task.task_type, payload_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbiter_shared::contract::AgentContract;
    use arbiter_shared::task::Task;
    use chrono::Utc;

    fn test_agent() -> AgentContract {
        AgentContract {
            id: "documenter".to_string(),
            version: 1,
            rules: vec!["Always cite source files".into()],
            constraints: vec!["Output must be valid Markdown".into()],
            capabilities: vec!["Generate documentation from source code".into()],
        }
    }

    fn test_task() -> Task {
        Task {
            id: "task-doc-1".into(),
            task_type: "generate documentation".into(),
            payload: serde_json::json!({"file": "src/lib.rs"}),
            submitted_at: Utc::now(),
        }
    }

    #[test]
    fn system_prompt_includes_rules_and_constraints() {
        let agent = test_agent();
        let prompt = build_system_prompt(&agent);

        assert!(prompt.contains("agent 'documenter'"));
        assert!(prompt.contains("Always cite source files"));
        assert!(prompt.contains("Output must be valid Markdown"));
        assert!(prompt.contains("Generate documentation from source code"));
    }

    #[test]
    fn user_message_includes_task_and_payload() {
        let task = test_task();
        let msg = build_user_message(&task);

        assert!(msg.contains("task-doc-1"));
        assert!(msg.contains("generate documentation"));
        assert!(msg.contains("src/lib.rs"));
    }
}
