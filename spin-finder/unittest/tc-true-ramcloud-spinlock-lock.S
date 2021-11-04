
0000000000509f60 <RAMCloud::SpinLock::lock()>:
  509f60:	push   %r15
  509f62:	push   %r14
  509f64:	lea    0x6ec4d(%rip),%r14        # 578bb8 <typeinfo name for RAMCloud::SideLog+0x18>
  509f6b:	push   %r13
  509f6d:	mov    %rdi,%r13
  509f70:	push   %r12
  509f72:	push   %rbp
  509f73:	lea    0x8(%rdi),%rbp
  509f77:	push   %rbx
  509f78:	xor    %ebx,%ebx
  509f7a:	sub    $0x38,%rsp
  509f7e:	lea    0x10(%rsp),%rax
  509f83:	mov    %rax,0x8(%rsp)
  509f88:	nopl   0x0(%rax,%rax,1)
  509f90:	mov    $0x1,%eax
  509f95:	xchg   %al,0x0(%rbp)
  509f98:	test   %al,%al
  509f9a:	je     50a050 <RAMCloud::SpinLock::lock()+0xf0>
  509fa0:	test   %rbx,%rbx
  509fa3:	jne    509fb8 <RAMCloud::SpinLock::lock()+0x58>
  509fa5:	rdtsc  
  509fa7:	mov    %rdx,%rbx
  509faa:	mov    %eax,%eax
  509fac:	shl    $0x20,%rbx
  509fb0:	or     %rax,%rbx
  509fb3:	jmp    509f90 <RAMCloud::SpinLock::lock()+0x30>
  509fb5:	nopl   (%rax)
  509fb8:	rdtsc  
  509fba:	mov    %rdx,%r12
  509fbd:	mov    %eax,%eax
  509fbf:	vxorpd %xmm0,%xmm0,%xmm0
  509fc3:	shl    $0x20,%r12
  509fc7:	or     %rax,%r12
  509fca:	mov    %r12,%r15
  509fcd:	sub    %rbx,%r15
  509fd0:	mov    %r15,%rdi
  509fd3:	callq  46bbe0 <RAMCloud::Cycles::toSeconds(unsigned long, double)>
  509fd8:	vucomisd 0x4f7c0(%rip),%xmm0        # 5597a0 <typeinfo name for std::_Sp_counted_deleter<RAMCloud::MultiFileStorage::Frame*, void (*)(RAMCloud::BackupStorage::Frame*), std::allocator<void>, (__gnu_cxx::_Lock_policy)2>+0x80>
  509fe0:	jbe    509f90 <RAMCloud::SpinLock::lock()+0x30>
  509fe2:	callq  4a3b40 <RAMCloud::Logger::get()>
  509fe7:	cmpl   $0x1,0x8(%rax)
  509feb:	jle    50a03c <RAMCloud::SpinLock::lock()+0xdc>
  509fed:	mov    0x10(%r13),%rdx
  509ff1:	mov    %r14,0x10(%rsp)
  509ff6:	sub    $0x8,%rsp
  509ffa:	mov    %rax,%rdi
  509ffd:	lea    0x6ec5c(%rip),%rcx        # 578c60 <RAMCloud::SpinLock::lock()::__func__>
  50a004:	lea    0x6ec35(%rip),%rsi        # 578c40 <RAMCloud::SpinLock::lock()::__PRETTY_FUNCTION__>
  50a00b:	movl   $0x5d,0x20(%rsp)
  50a013:	xor    %eax,%eax
  50a015:	mov    %rcx,0x28(%rsp)
  50a01a:	lea    0x6ebe7(%rip),%r9        # 578c08 <typeinfo name for RAMCloud::SideLog+0x68>
  50a021:	mov    $0x2,%ecx
  50a026:	mov    %rsi,0x30(%rsp)
  50a02b:	xor    %esi,%esi
  50a02d:	push   %rdx
  50a02e:	mov    0x18(%rsp),%r8
  50a033:	xor    %edx,%edx
  50a035:	callq  4a2d80 <RAMCloud::Logger::logMessage(bool, RAMCloud::LogModule, RAMCloud::LogLevel, RAMCloud::CodeLocation const&, char const*, ...)>
  50a03a:	pop    %rax
  50a03b:	pop    %rdx
  50a03c:	add    %r15,0x40(%r13)
  50a040:	mov    %r12,%rbx
  50a043:	jmpq   509f90 <RAMCloud::SpinLock::lock()+0x30>
  50a048:	nopl   0x0(%rax,%rax,1)
  50a050:	test   %rbx,%rbx
  50a053:	je     50a073 <RAMCloud::SpinLock::lock()+0x113>
  50a055:	rdtsc  
  50a057:	mov    %eax,%eax
  50a059:	shl    $0x20,%rdx
  50a05d:	addq   $0x1,0x38(%r13)
  50a062:	or     %rax,%rdx
  50a065:	mov    0x40(%r13),%rax
  50a069:	sub    %rbx,%rax
  50a06c:	add    %rdx,%rax
  50a06f:	mov    %rax,0x40(%r13)
  50a073:	addq   $0x1,0x30(%r13)
  50a078:	add    $0x38,%rsp
  50a07c:	pop    %rbx
  50a07d:	pop    %rbp
  50a07e:	pop    %r12
  50a080:	pop    %r13
  50a082:	pop    %r14
  50a084:	pop    %r15
  50a086:	retq   
  50a087:	nop
  50a088:	nopl   0x0(%rax,%rax,1)
