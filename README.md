# PEScan
PEScan is a tool to search the code section of a given PE module for a specific binary chunk.

### Sample output
```
> pescan.exe C:\Windows\system32\jscript9.dll d:\symbols\jscript9.pdb\406FB365F3334FBCA0F9AA16D2CC91FC1
Start searching...
+0007430b       Js::ByteCodeBufferBuilder::AddFunctionBody+db
+000c1a90       Lowerer::GenerateFastStElemI+1a2
+001116eb       PreVisitBlock+7d
+00115883       Js::JavascriptLibrary::InitializeError+4d
+0012a044       Recycler::Sweep+1e
+0014c8b7       NativeCodeGenerator::CodeGen+fa
+001506db       Js::InterpreterStackFrame::DoProfiledSetProperty<Js::OpLayoutElementCP const >+bf
+00151529       Js::InterpreterStackFrame::OP_ProfiledGetMethodProperty<Js::OpLayoutElementCP const >+7f
+00151723       Js::InterpreterStackFrame::OP_ProfiledGetProperty<Js::OpLayoutElementCP const >+ac
+0017494a       Js::JavascriptString::ToLocaleCaseHelper+2d
+00180f44       Parser::ParseStmtListNoASTCore+24
...
```
