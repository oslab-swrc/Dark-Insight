// TC_OUT __rpc_thread_svc_cleanup,0x13a590,0x13a5a7,0xe8(%rbx)
000000000013a580 <__rpc_thread_svc_cleanup>:
  13a580:	push   %rbx
  13a581:	callq  1398b0 <__rpc_thread_variables>
  13a586:	mov    %rax,%rbx
  13a589:	jmp    13a59d <__rpc_thread_svc_cleanup+0x1d>
  13a58b:	nopl   0x0(%rax,%rax,1)
  13a590:	mov    0x10(%rax),%rsi
  13a594:	mov    0x8(%rax),%rdi
  13a598:	callq  139cf0 <svc_unregister>
  13a59d:	mov    0xe8(%rbx),%rax
  13a5a4:	test   %rax,%rax
  13a5a7:	jne    13a590 <__rpc_thread_svc_cleanup+0x10>
  13a5a9:	pop    %rbx
  13a5aa:	retq   
  13a5ab:	nopl   0x0(%rax,%rax,1)

