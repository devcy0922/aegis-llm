use bytes::{Bytes, BytesMut};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResponsesRequest {
    pub model: Option<String>,
    pub input: Option<Value>,
    pub instructions: Option<String>,
    pub stream: Option<bool>,
    pub tools: Option<Vec<Value>>,
    pub tool_choice: Option<Value>,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub stop: Option<Value>,
    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

fn clean_schema(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut cleaned = serde_json::Map::new();
            for (k, v) in map {
                if k == "additionalProperties" || k == "strict" {
                    continue;
                }
                cleaned.insert(k.clone(), clean_schema(v));
            }
            Value::Object(cleaned)
        }
        Value::Array(arr) => {
            let cleaned: Vec<Value> = arr.iter().map(clean_schema).collect();
            Value::Array(cleaned)
        }
        _ => val.clone(),
    }
}

fn convert_tools(tools: &[Value]) -> Vec<Value> {
    let mut result = Vec::new();
    for tool in tools {
        if let Some(map) = tool.as_object() {
            if map.get("type").and_then(|t| t.as_str()) != Some("function") {
                continue;
            }
            let mut func = serde_json::Map::new();
            func.insert(
                "name".to_string(),
                map.get("name")
                    .cloned()
                    .unwrap_or(Value::String(String::new())),
            );
            func.insert(
                "description".to_string(),
                map.get("description")
                    .cloned()
                    .unwrap_or(Value::String(String::new())),
            );
            if let Some(params) = map.get("parameters") {
                func.insert("parameters".to_string(), clean_schema(params));
            }
            result.push(json!({
                "type": "function",
                "function": func
            }));
        }
    }
    result
}

fn convert_tool_choice(tc: &Value) -> Value {
    if tc.is_null() {
        Value::String("auto".to_string())
    } else if tc.is_string() {
        tc.clone()
    } else if let Some(map) = tc.as_object() {
        if map.get("type").and_then(|t| t.as_str()) == Some("function") {
            json!({
                "type": "function",
                "function": {
                    "name": map.get("name").cloned().unwrap_or(Value::String(String::new()))
                }
            })
        } else {
            Value::String("auto".to_string())
        }
    } else {
        Value::String("auto".to_string())
    }
}

pub fn convert_request_to_completions(req: ResponsesRequest) -> Value {
    let mut messages = Vec::new();

    // 1. instructions -> system message
    if let Some(ref inst) = req.instructions {
        if !inst.trim().is_empty() {
            messages.push(json!({
                "role": "system",
                "content": inst.trim()
            }));
        }
    }

    // 2. input parsing
    if let Some(ref input) = req.input {
        if let Some(text) = input.as_str() {
            messages.push(json!({
                "role": "user",
                "content": text
            }));
        } else if let Some(arr) = input.as_array() {
            let mut pending_tool_calls = Vec::new();
            let mut pending_reasoning = String::new();

            let flush_tool_calls =
                |msgs: &mut Vec<Value>, tc: &mut Vec<Value>, reason: &mut String| {
                    if !tc.is_empty() {
                        let mut msg = json!({
                            "role": "assistant",
                            "content": "",
                            "tool_calls": tc.clone()
                        });
                        if !reason.is_empty() {
                            msg.as_object_mut().unwrap().insert(
                                "reasoning_content".to_string(),
                                Value::String(reason.clone()),
                            );
                        }
                        msgs.push(msg);
                        tc.clear();
                        reason.clear();
                    }
                };

            for item in arr {
                if let Some(map) = item.as_object() {
                    let item_type = map.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match item_type {
                        "message" => {
                            flush_tool_calls(
                                &mut messages,
                                &mut pending_tool_calls,
                                &mut pending_reasoning,
                            );
                            let role = map.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                            let role = if role == "developer" { "system" } else { role };

                            let mut text_content = String::new();
                            let mut tool_calls = Vec::new();

                            if let Some(content) = map.get("content") {
                                if let Some(content_str) = content.as_str() {
                                    text_content = content_str.trim().to_string();
                                } else if let Some(content_arr) = content.as_array() {
                                    let mut texts = Vec::new();
                                    for c in content_arr {
                                        if let Some(c_map) = c.as_object() {
                                            let c_type = c_map
                                                .get("type")
                                                .and_then(|t| t.as_str())
                                                .unwrap_or("");
                                            if c_type == "text"
                                                || c_type == "input_text"
                                                || c_type == "output_text"
                                            {
                                                if let Some(t) =
                                                    c_map.get("text").and_then(|txt| txt.as_str())
                                                {
                                                    if !t.trim().is_empty() {
                                                        texts.push(t.to_string());
                                                    }
                                                }
                                            } else if c_type == "tool_call" {
                                                tool_calls.push(json!({
                                                    "id": c_map.get("id").cloned().unwrap_or(Value::String(String::new())),
                                                    "type": "function",
                                                    "function": {
                                                        "name": c_map.get("name").cloned().unwrap_or(Value::String(String::new())),
                                                        "arguments": c_map.get("arguments").cloned().unwrap_or(Value::String(String::new()))
                                                    }
                                                }));
                                            }
                                        }
                                    }
                                    text_content = texts.join("\n");
                                }
                            }

                            let reasoning = map
                                .get("reasoning_content")
                                .and_then(|r| r.as_str())
                                .unwrap_or("");

                            if !tool_calls.is_empty() {
                                let mut msg = json!({
                                    "role": role,
                                    "content": text_content,
                                    "tool_calls": tool_calls
                                });
                                if !reasoning.is_empty() {
                                    msg.as_object_mut().unwrap().insert(
                                        "reasoning_content".to_string(),
                                        Value::String(reasoning.to_string()),
                                    );
                                }
                                messages.push(msg);
                            } else if !text_content.is_empty() {
                                let mut msg = json!({
                                    "role": role,
                                    "content": text_content
                                });
                                if !reasoning.is_empty() {
                                    msg.as_object_mut().unwrap().insert(
                                        "reasoning_content".to_string(),
                                        Value::String(reasoning.to_string()),
                                    );
                                }
                                messages.push(msg);
                            }
                        }
                        "function_call" => {
                            pending_tool_calls.push(json!({
                                "id": map.get("call_id").cloned().unwrap_or(Value::String(String::new())),
                                "type": "function",
                                "function": {
                                    "name": map.get("name").cloned().unwrap_or(Value::String(String::new())),
                                    "arguments": map.get("arguments").cloned().unwrap_or(Value::String(String::new()))
                                }
                            }));
                            if let Some(reasoning) =
                                map.get("reasoning_content").and_then(|r| r.as_str())
                            {
                                if !reasoning.is_empty() && pending_reasoning.is_empty() {
                                    pending_reasoning = reasoning.to_string();
                                }
                            }
                        }
                        "function_call_output" => {
                            flush_tool_calls(
                                &mut messages,
                                &mut pending_tool_calls,
                                &mut pending_reasoning,
                            );
                            messages.push(json!({
                                "role": "tool",
                                "tool_call_id": map.get("call_id").cloned().unwrap_or(Value::String(String::new())),
                                "content": map.get("output").cloned().unwrap_or(Value::String(String::new()))
                            }));
                        }
                        _ => {}
                    }
                }
            }
            flush_tool_calls(
                &mut messages,
                &mut pending_tool_calls,
                &mut pending_reasoning,
            );
        }
    }

    // ── 메시지 순서 재정렬 (DeepSeek 및 일부 업스트림 강제 제약 준수) ──
    // tool 메시지는 반드시 그에 부합하는 tool_calls가 선언된 assistant 메시지 바로 뒤에 와야 합니다.
    let mut reordered = Vec::new();
    let mut i = 0;
    while i < messages.len() {
        let msg = &messages[i];
        if msg.get("role").and_then(|r| r.as_str()) == Some("assistant")
            && msg.get("tool_calls").is_some()
        {
            let tool_calls = msg
                .get("tool_calls")
                .and_then(|tc| tc.as_array())
                .cloned()
                .unwrap_or_default();
            let mut expected_ids: std::collections::HashSet<String> = tool_calls
                .iter()
                .filter_map(|tc| {
                    tc.get("id")
                        .and_then(|id| id.as_str())
                        .map(ToString::to_string)
                })
                .collect();

            let mut tool_msgs = Vec::new();
            let mut non_tool_msgs = Vec::new();
            let mut j = i + 1;
            while j < messages.len() && !expected_ids.is_empty() {
                let nxt = &messages[j];
                let nxt_role = nxt.get("role").and_then(|r| r.as_str()).unwrap_or("");
                if nxt_role == "tool" {
                    if let Some(tc_id) = nxt.get("tool_call_id").and_then(|id| id.as_str()) {
                        if expected_ids.contains(tc_id) {
                            expected_ids.remove(tc_id);
                            tool_msgs.push(nxt.clone());
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else if nxt_role == "system" || nxt_role == "developer" {
                    non_tool_msgs.push(nxt.clone());
                } else {
                    break;
                }
                j += 1;
            }
            reordered.extend(non_tool_msgs);
            reordered.push(msg.clone());
            reordered.extend(tool_msgs);
            i = j;
        } else {
            reordered.push(msg.clone());
            i += 1;
        }
    }

    let mut payload = json!({
        "messages": reordered
    });

    if let Some(ref m) = req.model {
        payload
            .as_object_mut()
            .unwrap()
            .insert("model".to_string(), Value::String(m.clone()));
    }
    if let Some(stream) = req.stream {
        payload
            .as_object_mut()
            .unwrap()
            .insert("stream".to_string(), Value::Bool(stream));
    }
    if let Some(ref t) = req.tools {
        let converted = convert_tools(t);
        if !converted.is_empty() {
            payload
                .as_object_mut()
                .unwrap()
                .insert("tools".to_string(), Value::Array(converted));
        }
    }
    if let Some(ref tc) = req.tool_choice {
        payload
            .as_object_mut()
            .unwrap()
            .insert("tool_choice".to_string(), convert_tool_choice(tc));
    }
    if let Some(temp) = req.temperature {
        payload
            .as_object_mut()
            .unwrap()
            .insert("temperature".to_string(), json!(temp));
    }
    if let Some(mt) = req.max_tokens {
        payload
            .as_object_mut()
            .unwrap()
            .insert("max_tokens".to_string(), json!(mt));
    }
    if let Some(ref st) = req.stop {
        payload
            .as_object_mut()
            .unwrap()
            .insert("stop".to_string(), st.clone());
    }

    // 그 외 파라미터 릴레이 (client_metadata 등은 굳이 전달하지 않음)
    payload
}

pub fn convert_response_to_responses(completions: Value) -> Value {
    let comp_obj = completions.as_object();
    let id = comp_obj
        .and_then(|o| o.get("id").and_then(|v| v.as_str()))
        .unwrap_or("");
    let model = comp_obj
        .and_then(|o| o.get("model").and_then(|v| v.as_str()))
        .unwrap_or("");
    let created = comp_obj
        .and_then(|o| o.get("created").and_then(|v| v.as_i64()))
        .unwrap_or(0);

    let mut output_items = Vec::new();

    if let Some(choices) = comp_obj.and_then(|o| o.get("choices").and_then(|v| v.as_array())) {
        if let Some(choice) = choices.first() {
            if let Some(message) = choice.get("message").and_then(|m| m.as_object()) {
                let reasoning = message
                    .get("reasoning_content")
                    .and_then(|r| r.as_str())
                    .unwrap_or("");

                // 1. Text content
                if let Some(content) = message.get("content").and_then(|c| c.as_str()) {
                    if !content.is_empty() {
                        let mut item = json!({
                            "id": format!("item_{}", Uuid::new_v4().simple()),
                            "type": "message",
                            "status": "completed",
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "text",
                                    "text": content
                                }
                            ]
                        });
                        if !reasoning.is_empty() {
                            item.as_object_mut().unwrap().insert(
                                "reasoning_content".to_string(),
                                Value::String(reasoning.to_string()),
                            );
                        }
                        output_items.push(item);
                    }
                }

                // 2. Tool calls (function calls)
                if let Some(tool_calls) = message.get("tool_calls").and_then(|tc| tc.as_array()) {
                    for tc in tool_calls {
                        if let Some(tc_obj) = tc.as_object() {
                            let tc_id = tc_obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let func = tc_obj.get("function").and_then(|f| f.as_object());
                            let name = func
                                .and_then(|f| f.get("name").and_then(|v| v.as_str()))
                                .unwrap_or("");
                            let args = func
                                .and_then(|f| f.get("arguments").and_then(|v| v.as_str()))
                                .unwrap_or("");

                            let mut item = json!({
                                "id": format!("item_{}", Uuid::new_v4().simple()),
                                "type": "function_call",
                                "status": "completed",
                                "call_id": tc_id,
                                "name": name,
                                "arguments": args
                            });
                            if !reasoning.is_empty() {
                                item.as_object_mut().unwrap().insert(
                                    "reasoning_content".to_string(),
                                    Value::String(reasoning.to_string()),
                                );
                            }
                            output_items.push(item);
                        }
                    }
                }
            }
        }
    }

    let usage = comp_obj.and_then(|o| o.get("usage"));

    json!({
        "id": format!("resp_{}", id.strip_prefix("chatcmpl-").unwrap_or(id)),
        "object": "response",
        "created_at": created,
        "model": model,
        "output": output_items,
        "usage": usage.cloned().unwrap_or(json!({
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0
        }))
    })
}

// ── SSE 스트림 변환기 구현 ──
pub struct ResponsesStreamAdapter<S> {
    inner: S,
    buffer: BytesMut,
    response_id: String,
    model: String,

    // Status tracking
    sent_created: bool,
    sent_in_progress: bool,

    text_item_id: String,
    text_started: bool,
    has_text: bool,
    full_text: String,
    full_reasoning: String,

    // index -> (item_id, call_id, name, arguments, started)
    tool_calls: HashMap<u64, (String, String, String, String, bool)>,

    input_tokens: u64,
    output_tokens: u64,
    seq: u64,
    finished: bool,
}

impl<S> ResponsesStreamAdapter<S> {
    pub fn new(inner: S, req_model: Option<String>) -> Self {
        Self {
            inner,
            buffer: BytesMut::new(),
            response_id: format!("resp_{}", Uuid::new_v4().simple()),
            model: req_model.unwrap_or_else(|| "unknown".to_string()),
            sent_created: false,
            sent_in_progress: false,
            text_item_id: format!("item_{}", Uuid::new_v4().simple()),
            text_started: false,
            has_text: false,
            full_text: String::new(),
            full_reasoning: String::new(),
            tool_calls: HashMap::new(),
            input_tokens: 0,
            output_tokens: 0,
            seq: 0,
            finished: false,
        }
    }

    fn make_sse(event: &str, data: &Value) -> Bytes {
        let s = format!(
            "event: {}\ndata: {}\n\n",
            event,
            serde_json::to_string(data).unwrap()
        );
        Bytes::from(s)
    }
}

impl<S> Stream for ResponsesStreamAdapter<S>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }

        // 1. lifecycle 선행 이벤트 전송
        if !self.sent_created {
            self.sent_created = true;
            let data = json!({
                "type": "response.created",
                "response": {
                    "id": self.response_id,
                    "object": "response",
                    "status": "in_progress",
                    "model": self.model,
                    "output": [],
                    "usage": null
                }
            });
            return Poll::Ready(Some(Ok(Self::make_sse("response.created", &data))));
        }
        if !self.sent_in_progress {
            self.sent_in_progress = true;
            let data = json!({
                "type": "response.in_progress",
                "response": {
                    "id": self.response_id,
                    "object": "response",
                    "status": "in_progress",
                    "model": self.model,
                    "output": [],
                    "usage": null
                }
            });
            return Poll::Ready(Some(Ok(Self::make_sse("response.in_progress", &data))));
        }

        // 2. inner stream 수신 및 버퍼링 처리
        loop {
            // 버퍼에서 한 줄 추출 시도
            if let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
                let line_bytes = self.buffer.split_to(pos + 1);
                let line = String::from_utf8_lossy(&line_bytes[..pos]);
                let line = line.trim();

                if line.is_empty() {
                    continue;
                }

                if !line.starts_with("data: ") {
                    continue;
                }

                let raw_data = &line[6..];
                if raw_data == "[DONE]" {
                    continue;
                }

                let chunk: Value = match serde_json::from_str(raw_data) {
                    Ok(val) => val,
                    Err(_) => continue,
                };

                // usage 및 model 정보 추출
                if let Some(m) = chunk.get("model").and_then(|v| v.as_str()) {
                    self.model = m.to_string();
                }
                if let Some(usage) = chunk.get("usage").and_then(|u| u.as_object()) {
                    self.input_tokens = usage
                        .get("prompt_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    self.output_tokens = usage
                        .get("completion_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                }

                if let Some(choices) = chunk.get("choices").and_then(|v| v.as_array()) {
                    if let Some(choice) = choices.first() {
                        let delta = choice.get("delta").and_then(|d| d.as_object());
                        if let Some(delta) = delta {
                            // reasoning_content 캡처
                            if let Some(reasoning) =
                                delta.get("reasoning_content").and_then(|v| v.as_str())
                            {
                                self.full_reasoning.push_str(reasoning);
                            }

                            // content 캡처 및 sse 전송
                            if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
                                if !content.is_empty() {
                                    if !self.text_started {
                                        self.text_started = true;
                                        self.has_text = true;
                                        // output_item.added 전송
                                        let added_data = json!({
                                            "type": "response.output_item.added",
                                            "output_index": 0,
                                            "item": {
                                                "id": self.text_item_id,
                                                "type": "message",
                                                "status": "in_progress",
                                                "role": "assistant",
                                                "content": []
                                            }
                                        });
                                        // 다음 delta 처리를 위해 버퍼 복원 및 sse 쏘기
                                        // 줄 처리가 아닌 이벤트 분기이므로, 이 added 이벤트를 우선 yield하도록 함
                                        let part_data = json!({
                                            "type": "response.content_part.added",
                                            "item_id": self.text_item_id,
                                            "output_index": 0,
                                            "content_index": 0,
                                            "part": {
                                                "type": "text",
                                                "text": ""
                                            }
                                        });
                                        self.full_text.push_str(content);
                                        self.seq += 1;
                                        let delta_data = json!({
                                            "type": "response.output_text.delta",
                                            "delta": content,
                                            "item_id": self.text_item_id,
                                            "output_index": 0,
                                            "content_index": 0,
                                            "sequence_number": self.seq
                                        });
                                        // 3개 이벤트를 하나로 묶어서 반환 (안전하게 스트링 체이닝)
                                        let s1 = format!(
                                            "event: response.output_item.added\ndata: {}\n\n",
                                            serde_json::to_string(&added_data).unwrap()
                                        );
                                        let s2 = format!(
                                            "event: response.content_part.added\ndata: {}\n\n",
                                            serde_json::to_string(&part_data).unwrap()
                                        );
                                        let s3 = format!(
                                            "event: response.output_text.delta\ndata: {}\n\n",
                                            serde_json::to_string(&delta_data).unwrap()
                                        );
                                        return Poll::Ready(Some(Ok(Bytes::from(format!(
                                            "{}{}{}",
                                            s1, s2, s3
                                        )))));
                                    }

                                    self.full_text.push_str(content);
                                    self.seq += 1;
                                    let delta_data = json!({
                                        "type": "response.output_text.delta",
                                        "delta": content,
                                        "item_id": self.text_item_id,
                                        "output_index": 0,
                                        "content_index": 0,
                                        "sequence_number": self.seq
                                    });
                                    return Poll::Ready(Some(Ok(Self::make_sse(
                                        "response.output_text.delta",
                                        &delta_data,
                                    ))));
                                }
                            }

                            // tool_calls 캡처 및 sse 전송
                            if let Some(tcs) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                                for tc in tcs {
                                    if let Some(tc_obj) = tc.as_object() {
                                        let idx = tc_obj
                                            .get("index")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let tc_id =
                                            tc_obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                        let func =
                                            tc_obj.get("function").and_then(|f| f.as_object());
                                        let name = func
                                            .and_then(|f| f.get("name").and_then(|v| v.as_str()))
                                            .unwrap_or("");
                                        let args_delta = func
                                            .and_then(|f| {
                                                f.get("arguments").and_then(|v| v.as_str())
                                            })
                                            .unwrap_or("");

                                        self.tool_calls.entry(idx).or_insert_with(|| {
                                            (
                                                format!("item_{}", Uuid::new_v4().simple()),
                                                tc_id.to_string(),
                                                name.to_string(),
                                                String::new(),
                                                false,
                                            )
                                        });

                                        let has_text = self.has_text;
                                        let acc = self.tool_calls.get_mut(&idx).unwrap();
                                        if !tc_id.is_empty() {
                                            acc.1 = tc_id.to_string();
                                        }
                                        if !name.is_empty() {
                                            acc.2 = name.to_string();
                                        }

                                        if !args_delta.is_empty() {
                                            acc.3.push_str(args_delta);
                                            let out_idx = if has_text { 1 } else { 0 } + idx;

                                            if !acc.4 {
                                                acc.4 = true;
                                                let added_data = json!({
                                                    "type": "response.output_item.added",
                                                    "output_index": out_idx,
                                                    "item": {
                                                        "id": acc.0,
                                                        "type": "function_call",
                                                        "status": "in_progress",
                                                        "call_id": acc.1,
                                                        "name": acc.2,
                                                        "arguments": ""
                                                    }
                                                });
                                                let delta_data = json!({
                                                    "type": "response.function_call_arguments.delta",
                                                    "item_id": acc.0,
                                                    "output_index": out_idx,
                                                    "delta": args_delta
                                                });
                                                let s1 = format!("event: response.output_item.added\ndata: {}\n\n", serde_json::to_string(&added_data).unwrap());
                                                let s2 = format!("event: response.function_call_arguments.delta\ndata: {}\n\n", serde_json::to_string(&delta_data).unwrap());
                                                return Poll::Ready(Some(Ok(Bytes::from(
                                                    format!("{}{}", s1, s2),
                                                ))));
                                            } else {
                                                let delta_data = json!({
                                                    "type": "response.function_call_arguments.delta",
                                                    "item_id": acc.0,
                                                    "output_index": out_idx,
                                                    "delta": args_delta
                                                });
                                                return Poll::Ready(Some(Ok(Self::make_sse(
                                                    "response.function_call_arguments.delta",
                                                    &delta_data,
                                                ))));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                // inner stream으로부터 다음 chunk poll
                match Stream::poll_next(Pin::new(&mut self.inner), cx) {
                    Poll::Ready(Some(Ok(bytes))) => {
                        self.buffer.extend_from_slice(&bytes);
                    }
                    Poll::Ready(Some(Err(err))) => {
                        return Poll::Ready(Some(Err(err)));
                    }
                    Poll::Ready(None) => {
                        // Upstream 스트림이 끝남 -> 완료 이벤트 조립
                        self.finished = true;

                        let mut final_events = String::new();
                        let mut output_items = Vec::new();

                        if self.has_text {
                            let text_done = json!({
                                "type": "response.output_text.done",
                                "text": self.full_text,
                                "item_id": self.text_item_id,
                                "output_index": 0,
                                "content_index": 0
                            });
                            let part_done = json!({
                                "type": "response.content_part.done",
                                "item_id": self.text_item_id,
                                "output_index": 0,
                                "content_index": 0,
                                "part": {
                                    "type": "text",
                                    "text": self.full_text
                                }
                            });
                            let mut text_item = json!({
                                "id": self.text_item_id,
                                "type": "message",
                                "status": "completed",
                                "role": "assistant",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": self.full_text
                                    }
                                ]
                            });
                            if !self.full_reasoning.is_empty() {
                                text_item.as_object_mut().unwrap().insert(
                                    "reasoning_content".to_string(),
                                    Value::String(self.full_reasoning.clone()),
                                );
                            }
                            let item_done = json!({
                                "type": "response.output_item.done",
                                "output_index": 0,
                                "item": text_item
                            });

                            final_events.push_str(&format!(
                                "event: response.output_text.done\ndata: {}\n\n",
                                serde_json::to_string(&text_done).unwrap()
                            ));
                            final_events.push_str(&format!(
                                "event: response.content_part.done\ndata: {}\n\n",
                                serde_json::to_string(&part_done).unwrap()
                            ));
                            final_events.push_str(&format!(
                                "event: response.output_item.done\ndata: {}\n\n",
                                serde_json::to_string(&item_done).unwrap()
                            ));

                            output_items.push(json!({
                                "id": self.text_item_id,
                                "type": "message",
                                "status": "completed",
                                "role": "assistant",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": self.full_text
                                    }
                                ],
                                "reasoning_content": if self.full_reasoning.is_empty() { Value::Null } else { Value::String(self.full_reasoning.clone()) }
                            }));
                        }

                        // tool_calls 완료
                        let mut sorted_keys: Vec<&u64> = self.tool_calls.keys().collect();
                        sorted_keys.sort();
                        for idx in sorted_keys {
                            let acc = &self.tool_calls[idx];
                            let out_idx = if self.has_text { 1 } else { 0 } + idx;

                            let arg_done = json!({
                                "type": "response.function_call_arguments.done",
                                "item_id": acc.0,
                                "output_index": out_idx,
                                "arguments": acc.3
                            });
                            let mut func_item = json!({
                                "id": acc.0,
                                "type": "function_call",
                                "status": "completed",
                                "call_id": acc.1,
                                "name": acc.2,
                                "arguments": acc.3
                            });
                            if !self.full_reasoning.is_empty() {
                                func_item.as_object_mut().unwrap().insert(
                                    "reasoning_content".to_string(),
                                    Value::String(self.full_reasoning.clone()),
                                );
                            }
                            let item_done = json!({
                                "type": "response.output_item.done",
                                "output_index": out_idx,
                                "item": func_item
                            });

                            final_events.push_str(&format!(
                                "event: response.function_call_arguments.done\ndata: {}\n\n",
                                serde_json::to_string(&arg_done).unwrap()
                            ));
                            final_events.push_str(&format!(
                                "event: response.output_item.done\ndata: {}\n\n",
                                serde_json::to_string(&item_done).unwrap()
                            ));

                            output_items.push(json!({
                                "id": acc.0,
                                "type": "function_call",
                                "status": "completed",
                                "call_id": acc.1,
                                "name": acc.2,
                                "arguments": acc.3,
                                "reasoning_content": if self.full_reasoning.is_empty() { Value::Null } else { Value::String(self.full_reasoning.clone()) }
                            }));
                        }

                        // 최종 response.completed
                        let completed_data = json!({
                            "type": "response.completed",
                            "response": {
                                "id": self.response_id,
                                "object": "response",
                                "status": "completed",
                                "model": self.model,
                                "output": output_items,
                                "usage": {
                                    "prompt_tokens": if self.input_tokens > 0 { self.input_tokens } else { 10 },
                                    "completion_tokens": if self.output_tokens > 0 { self.output_tokens } else { self.seq },
                                    "total_tokens": (if self.input_tokens > 0 { self.input_tokens } else { 10 }) + (if self.output_tokens > 0 { self.output_tokens } else { self.seq })
                                }
                            }
                        });
                        final_events.push_str(&format!(
                            "event: response.completed\ndata: {}\n\n",
                            serde_json::to_string(&completed_data).unwrap()
                        ));

                        return Poll::Ready(Some(Ok(Bytes::from(final_events))));
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}
