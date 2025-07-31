# LangChain & LangGraph Conventions

## Project Structure
```
src/
├── chains/          # LangChain chains
├── agents/          # Custom agents & tools
├── prompts/         # Centralized prompt templates
├── retrievers/      # Custom retrievers
├── memory/          # Memory implementations
├── graphs/          # LangGraph workflows
└── utils/           # LLM utilities
```

## Environment Configuration
- LangChain-specific settings in separate Pydantic class
- Required: `OPENAI_API_KEY`, `LANGCHAIN_API_KEY` (for tracing)
- Optional: `ANTHROPIC_API_KEY`, `PINECONE_API_KEY`
- Enable tracing: `LANGCHAIN_TRACING_V2=true`

## LLM Setup Pattern
- Cached LLM instances with `@lru_cache()`
- Factory functions: `get_chat_model(model_name, temperature)`
- Default to GPT-4o, temperature=0.0 for consistency
- Separate embedding model function: `get_embeddings()`

## Prompt Management
- Centralized `PromptTemplates` class with class methods
- Use `ChatPromptTemplate.from_template()` or `from_messages()`
- Store system prompts as class constants
- Method pattern: `@classmethod get_prompt_name(cls) -> ChatPromptTemplate`

## Chain Architecture
- Abstract `BaseChain` class with `arun()` and `run()` methods
- Input/output with Pydantic models: `ChainInput`, `ChainOutput`
- Setup method for chain-specific initialization
- Always include metadata in outputs (sources, confidence, etc.)

## Agent & Tools Pattern
- Custom tools inherit from `BaseTool`
- Tool input schemas with Pydantic `BaseModel`
- Implement both `_run()` and `_arun()` methods
- Tools should handle their own error cases gracefully

## LangGraph Workflows
- State as `TypedDict` with annotated list fields
- Node functions take state, return state updates
- Conditional edges with `should_*` functions
- Compile graph once, reuse for multiple executions
- Pattern: `workflow.add_node(name, function)`

## Memory Implementation
- Custom memory classes inherit from `BaseChatMemory`
- Implement `load_history()` and `save_history()` methods
- File-based persistence for development
- Database persistence for production

## Error Handling
- Wrap LLM calls in try/catch for `OutputParserException`
- Retry logic for API failures
- Graceful degradation when services unavailable
- Log all LLM interactions for debugging

## Testing Strategies
- Mock LLM responses for unit tests
- Use `AsyncMock` for async LLM operations
- Test chain logic, not LLM outputs
- Fixture-based test data for consistent inputs

## Best Practices
- Prefer async methods (`agenerate`, `ainvoke`) for better performance
- Keep prompts concise and specific
- Use structured outputs when possible
- Monitor token usage and costs
- Implement proper timeout handling
- Cache expensive operations (embeddings, etc.)
