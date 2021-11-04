// TC_OUT
0000000000000009 <__write_nocancel>:
   9:	mov    $0x1,%eax
   e:	syscall 
  10:	cmp    $0xfffffffffffff001,%rax
  16:	jae    1c <__write_nocancel+0x13>
  1c:	retq   
  1d:	sub    $0x8,%rsp
  21:	callq  26 <__write_nocancel+0x1d>
  26:	mov    %rax,(%rsp)
  2a:	mov    $0x1,%eax
  2f:	syscall 
  31:	mov    (%rsp),%rdi
  35:	mov    %rax,%rdx
  38:	callq  3d <__write_nocancel+0x34>
  3d:	mov    %rdx,%rax
  40:	add    $0x8,%rsp
  44:	cmp    $0xfffffffffffff001,%rax
  4a:	jae    50 <__write_nocancel+0x47>
  50:	retq   

