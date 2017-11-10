# PEScan
PEScan is a tool to search the code section of a given PE module for a specific binary chunk.

### Sample output
```
> bin\amd64\pescan.exe
USAGE: PESCAN <PE> <pattern>

Pattern examples:

  <Stack Pivot>
  94:c3 -- xchg eax,esp
           ret

  <Get x64 TEB address>
  65488b042530000000 -- mov rax,qword ptr gs:[30h]

> bin\amd64\pescan.exe C:\Windows\system32\mshtml.dll 65488b042530000000
Start searching...
+000a603a       MemProtectThreadContext::MemProtectThreadContext +6a
+004ff8ce
+004ff9b7
+00f37f8b

> bin\x86\pescan.exe C:\Windows\system32\jscript9.dll 94:c3
Start searching...
+0007430b       Js::ByteCodeBufferBuilder::AddFunctionBody +db
+00085270
+000c1a90       Lowerer::GenerateFastStElemI +1a2
+000cde3d
+000e1ae7
+001116eb       PreVisitBlock +7d
+00115883       Js::JavascriptLibrary::InitializeError +4d
+0012a044       Recycler::Sweep +1e
+0014c4a0
+0014c8b7       NativeCodeGenerator::CodeGen +fa
+001506db       Js::InterpreterStackFrame::DoProfiledSetProperty<Js::OpLayoutElementCP const > +bf
+00151529       Js::InterpreterStackFrame::OP_ProfiledGetMethodProperty<Js::OpLayoutElementCP const > +7f
+00151723       Js::InterpreterStackFrame::OP_ProfiledGetProperty<Js::OpLayoutElementCP const > +ac
+0017494a       Js::JavascriptString::ToLocaleCaseHelper +2d
+00180f44       Parser::ParseStmtListNoASTCore +24
+001e734b
...

```
