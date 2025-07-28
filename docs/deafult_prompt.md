**NEVER** modify this document, this is for the human to edit to guide the work to be done.

**Do NOT** worry about keeping the git repo up top date.  I'll take care of that offline.

Under no circumstances should you HARDCODE results to make it easier to create the report.  This is a tool that will need to be able to identify any of the tens of thousands of MCP Servers.

## Instructions 
- Use the `docs/Design.md` as the authoritative source for the original project. **REFERENCE ONLY**
- Use the `docs/Design-inspect-mcp.md` as the design guide for the current phase of work. **REFERENCE ONLY**
- Use the `docs/Design-Threat-Analysis.md` for threat analysis system design. **REFERENCE ONLY**
- Use the `docs/Design-Threat-Analysis-Report.md` for threat analysis report design. **REFERENCE ONLY**
- Use the `docs/task_list.md` previously used for the project development. **Complete - REFERENCE ONLY**
- Use the `docs/task_list-inspect-mcp.md` current task_list to guide work **Complete - REFERENCE ONLY**
- Use the `docs/task-list-threat-analysis.md` for threat analysis implementation status. **Complete for now - REFERENCE ONLY**
- Use the `docs/task-list-threat-analysis-report.md` for threat analysis preport implementation status. **to be added**
- Use the `docs/notes.md` for notable aspects of the project.
- Use the `docs/uml.txt` for reference for the code that exists in classes.
- Use the `docs/module-functions.txt`  for code that is not in classes.
- Use the `docs/tree-structure.txt` to see thefile layout of the project.
- Use doc-tools tool to create the uml, module-functions and tree structure docs.   These docs will not exist until there is code and  the tool has run.
- The folder `docs/conventions/` contains documents that describe the coding conventions used in this project for a number of differnt libraries.
- Use context7 tool to find usage and examples for many code libraries.
- Use the exa tool to search the web.

## Must adhere to
- Most importantly **NEVER** use `asyncio`, this causes massive problems when coding in python.
- **Always** use the `venv`, to load requirements, and launch the application.
- The tools run from where Cursor is running from do if you want to use a relative project path it might break some tools, this project is located `/ai/work/cursor/mcp-hunt`, if you use fully qualified paths you will get betterresults.
- Limit what we hard code, situations change in different environments.  While we see something in this environment, we need to be able to run the tool in many environments.
- Most importantly **NEVER** use `asyncio`, this causes massive problems when coding in python.
- Don't use `!` in bash scripts it don't work well with the tools.
- Under no circumstances should you HARDCODE results to make it easier to create the report.  This is a tool that will need to be able to identify any of the tens of thousands of MCP Servers.
