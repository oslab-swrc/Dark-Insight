// TC_OUT g_pointer_bit_lock,0x20080,0x20085,0x0(%rbx)
// TC_OUT g_pointer_bit_lock,0x20098,0x2009e,0x0(%rbx)
// TC_OUT g_pointer_bit_lock,0x20098,0x200c6,0x0(%rbx)
0000000000020030 <g_pointer_bit_lock>:
   20030:	cmp    $0x1f,%esi
   20033:	jg     200d0 <g_pointer_bit_lock+0xa0>
   20039:	mov    %rdi,%rax
   2003c:	movabs $0x2e8ba2e8ba2e8ba3,%rdx
   20046:	push   %r13
   20048:	mul    %rdx
   2004b:	push   %r12
   2004d:	push   %rbp
   2004e:	push   %rbx
   2004f:	mov    $0x1,%ebp
   20054:	mov    %esi,%ecx
   20056:	mov    %rdi,%rbx
   20059:	movslq %esi,%r12
   2005c:	shl    %cl,%ebp
   2005e:	sub    $0x8,%rsp
   20062:	shr    %rdx
   20065:	lea    (%rdx,%rdx,4),%rax
   20069:	lea    (%rdx,%rax,2),%rax
   2006d:	mov    %edi,%edx
   2006f:	sub    %eax,%edx
   20071:	lea    0x2edc48(%rip),%rax        # 30dcc0 <g_thread_use_default_impl+0x38>
   20078:	lea    (%rax,%rdx,4),%r13
   2007c:	nopl   0x0(%rax)
   20080:	lock bts %r12,(%rbx)
   20085:	jb     20098 <g_pointer_bit_lock+0x68>
   20087:	add    $0x8,%rsp
   2008b:	pop    %rbx
   2008c:	pop    %rbp
   2008d:	pop    %r12
   2008f:	pop    %r13
   20091:	retq   
   20092:	nopw   0x0(%rax,%rax,1)
   20098:	mov    (%rbx),%rcx
   2009b:	test   %rbp,%rcx
   2009e:	je     20080 <g_pointer_bit_lock+0x50>
   200a0:	lock addl $0x1,0x0(%r13)
   200a6:	xor    %r8d,%r8d
   200a9:	mov    $0x80,%edx
   200ae:	mov    $0xca,%edi
   200b3:	movslq %ecx,%rcx
   200b6:	mov    %rbx,%rsi
   200b9:	xor    %eax,%eax
   200bb:	callq  1a050 <syscall@plt>
   200c0:	lock subl $0x1,0x0(%r13)
   200c6:	jmp    20080 <g_pointer_bit_lock+0x50>
   200c8:	nopl   0x0(%rax,%rax,1)
   200d0:	lea    0x7272a(%rip),%rdx        # 92801 <_fini+0x12d5>
   200d7:	lea    0x72772(%rip),%rsi        # 92850 <_fini+0x1324>
   200de:	lea    0x71469(%rip),%rdi        # 9154e <_fini+0x22>
   200e5:	jmpq   50f60 <g_return_if_fail_warning>
   200ea:	nopw   0x0(%rax,%rax,1)

