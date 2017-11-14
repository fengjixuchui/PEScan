# PEScan
PEScan is a tool to search the code section of a given PE module for a specific binary chunk.

### Sample output
```
> bin\amd64\pescan.exe
USAGE: PESCAN <PE> <pattern>

Set _NT_SYMBOL_PATH environment variable to get a symbol name for RVA,
and place symsrv.exe in a directory that is visible from PESCAN.

Pattern examples:

  <Stack Pivot>
  94:c3 -- xchg eax,esp
           ret

  <Get x64 TEB address>
  65488b042530000000 -- mov rax,qword ptr gs:[30h]

> bin\amd64\pescan.exe C:\Windows\system32\mshtml.dll 65488b042530000000
Start searching...
+00039a56       mshtml!MemProtectThreadContext::MemProtectThreadContext +6a
+004fcb6e
+004fcc57
+00f378bb

> bin\amd64\pescan.exe C:\Windows\syswow64\jscript9.dll 94:c3
Start searching...
+0007fba0
+000a1974       jscript9!Parser::ParseStmtListNoASTCore +24
+000c0b72       jscript9!Js::JavascriptLibrary::InitializeError +4d
+000d3600
+000d3a17       jscript9!NativeCodeGenerator::CodeGen +fa
+000d783b       jscript9!Js::InterpreterStackFrame::DoProfiledSetProperty<Js::OpLayoutElementCP const > +bf
+000d8689       jscript9!Js::InterpreterStackFrame::OP_ProfiledGetMethodProperty<Js::OpLayoutElementCP const > +7f
+000d8883       jscript9!Js::InterpreterStackFrame::OP_ProfiledGetProperty<Js::OpLayoutElementCP const > +ac
+000e6c80       jscript9!Lowerer::GenerateFastStElemI +1a2
+000f301d
+00106c97
+00141224       jscript9!Recycler::Sweep +1e
+0016596b       jscript9!PreVisitBlock +7d
+0016e9db       jscript9!UnifiedRegex::ConcatNode::SupportsPrefixSkipping +2b
+0019af74       jscript9!Js::JavascriptString::ToLocaleCaseHelper +2d
+001e4bae
...
```
