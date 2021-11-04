0000000000529500 <RAMCloud::SpinLock::lock()>:
  529500:	push   %r15
  529502:	push   %r14
  529504:	lea    0x70f2d(%rip),%r14        # 59a438 <typeinfo name for RAMCloud::SideLog+0x18>
  52950b:	push   %r13
  52950d:	mov    %rdi,%r13
  529510:	push   %r12
  529512:	push   %rbp
  529513:	lea    0x8(%rdi),%rbp
  529517:	push   %rbx
  529518:	xor    %ebx,%ebx
  52951a:	sub    $0x38,%rsp
  52951e:	lea    0x10(%rsp),%rax
  529523:	mov    %rax,0x8(%rsp)
  529528:	nopl   0x0(%rax,%rax,1)
  529530:	mov    $0x1,%eax
  529535:	xchg   %al,0x0(%rbp)
  529538:	test   %al,%al
  52953a:	je     5295f0 <RAMCloud::SpinLock::lock()+0xf0>
  529540:	test   %rbx,%rbx
  529543:	jne    529558 <RAMCloud::SpinLock::lock()+0x58>
  529545:	rdtsc  
  529547:	mov    %rdx,%rbx
  52954a:	mov    %eax,%eax
  52954c:	shl    $0x20,%rbx
  529550:	or     %rax,%rbx
  529553:	jmp    529530 <RAMCloud::SpinLock::lock()+0x30>
  529555:	nopl   (%rax)
  529558:	rdtsc  
  52955a:	mov    %rdx,%r12
  52955d:	mov    %eax,%eax
  52955f:	vxorpd %xmm0,%xmm0,%xmm0
  529563:	shl    $0x20,%r12
  529567:	or     %rax,%r12
  52956a:	mov    %r12,%r15
  52956d:	sub    %rbx,%r15
  529570:	mov    %r15,%rdi
  529573:	callq  48a240 <RAMCloud::Cycles::toSeconds(unsigned long, double)>
  529578:	vucomisd 0x5eca0(%rip),%xmm0        # 588220 <typeinfo name for std::thread::_State_impl<std::_Bind_simple<void (*(RAMCloud::LogCleaner*, RAMCloud::Context*))(RAMCloud::LogCleaner*, RAMCloud::Context*)> >+0x60>
  529580:	jbe    529530 <RAMCloud::SpinLock::lock()+0x30>
  529582:	callq  4c2db0 <RAMCloud::Logger::get()>
  529587:	cmpl   $0x1,0x8(%rax)
  52958b:	jle    5295dc <RAMCloud::SpinLock::lock()+0xdc>
  52958d:	mov    0x10(%r13),%rdx
  529591:	mov    %r14,0x10(%rsp)
  529596:	sub    $0x8,%rsp
  52959a:	mov    %rax,%rdi
  52959d:	lea    0x70f3c(%rip),%rcx        # 59a4e0 <RAMCloud::SpinLock::lock()::__func__>
  5295a4:	lea    0x70f15(%rip),%rsi        # 59a4c0 <RAMCloud::SpinLock::lock()::__PRETTY_FUNCTION__>
  5295ab:	movl   $0x5d,0x20(%rsp)
  5295b3:	xor    %eax,%eax
  5295b5:	mov    %rcx,0x28(%rsp)
  5295ba:	lea    0x70ec7(%rip),%r9        # 59a488 <typeinfo name for RAMCloud::SideLog+0x68>
  5295c1:	mov    $0x2,%ecx
  5295c6:	mov    %rsi,0x30(%rsp)
  5295cb:	xor    %esi,%esi
  5295cd:	push   %rdx
  5295ce:	mov    0x18(%rsp),%r8
  5295d3:	xor    %edx,%edx
  5295d5:	callq  4c1ff0 <RAMCloud::Logger::logMessage(bool, RAMCloud::LogModule, RAMCloud::LogLevel, RAMCloud::CodeLocation const&, char const*, ...)>
  5295da:	pop    %rax
  5295db:	pop    %rdx
  5295dc:	add    %r15,0x40(%r13)
  5295e0:	mov    %r12,%rbx
  5295e3:	jmpq   529530 <RAMCloud::SpinLock::lock()+0x30>
  5295e8:	nopl   0x0(%rax,%rax,1)
  5295f0:	test   %rbx,%rbx
  5295f3:	je     529613 <RAMCloud::SpinLock::lock()+0x113>
  5295f5:	rdtsc  
  5295f7:	mov    %eax,%eax
  5295f9:	shl    $0x20,%rdx
  5295fd:	addq   $0x1,0x38(%r13)
  529602:	or     %rax,%rdx
  529605:	mov    0x40(%r13),%rax
  529609:	sub    %rbx,%rax
  52960c:	add    %rdx,%rax
  52960f:	mov    %rax,0x40(%r13)
  529613:	addq   $0x1,0x30(%r13)
  529618:	add    $0x38,%rsp
  52961c:	pop    %rbx
  52961d:	pop    %rbp
  52961e:	pop    %r12
  529620:	pop    %r13
  529622:	pop    %r14
  529624:	pop    %r15
  529626:	retq   
  529627:	nop
  529628:	nopl   0x0(%rax,%rax,1)
