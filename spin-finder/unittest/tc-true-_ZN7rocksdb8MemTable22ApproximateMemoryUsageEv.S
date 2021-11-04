// TC_OUT _ZN7rocksdb8MemTable22ApproximateMemoryUsageEv,0x51c060,0x51c08d,0x0(%r13)
000000000051c020 <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv>:
  51c020:	push   %rbp
  51c021:	mov    %rsp,%rbp
  51c024:	push   %r14
  51c026:	push   %r13
  51c028:	lea    0x958(%rdi),%r13
  51c02f:	push   %r12
  51c031:	push   %rbx
  51c032:	mov    %rdi,%rbx
  51c035:	sub    $0x20,%rsp
  51c039:	mov    %r13,-0x30(%rbp)
  51c03d:	cmpq   $0x0,0xd8(%rdi)
  51c045:	movb   $0x0,-0x28(%rbp)
  51c049:	je     51c094 <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0x74>
  51c04b:	test   %r13,%r13
  51c04e:	je     51c136 <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0x116>
  51c054:	xor    %r12d,%r12d
  51c057:	mov    $0x1,%r14d
  51c05d:	jmp    51c071 <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0x51>
  51c05f:	nop
  51c060:	pause  
  51c062:	cmp    $0x64,%r12
  51c066:	jbe    51c06d <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0x4d>
  51c068:	callq  408580 <sched_yield@plt>
  51c06d:	add    $0x1,%r12
  51c071:	movzbl 0x0(%r13),%eax
  51c076:	test   %al,%al
  51c078:	setne  %al
  51c07b:	test   %al,%al
  51c07d:	mov    %al,-0x31(%rbp)
  51c080:	jne    51c060 <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0x40>
  51c082:	lock cmpxchg %r14b,0x0(%r13)
  51c088:	je     51c090 <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0x70>
  51c08a:	mov    %al,-0x31(%rbp)
  51c08d:	jmp    51c060 <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0x40>
  51c08f:	nop
  51c090:	movb   $0x1,-0x28(%rbp)
  51c094:	mov    0x908(%rbx),%rax
  51c09b:	mov    0x950(%rbx),%rdx
  51c0a2:	mov    0xe0(%rbx),%rsi
  51c0a9:	sub    0x8f8(%rbx),%rax
  51c0b0:	sub    0x940(%rbx),%rdx
  51c0b7:	and    $0xfffffffffffffff8,%rax
  51c0bb:	lea    (%rdx,%rax,1),%r12
  51c0bf:	xor    %edx,%edx
  51c0c1:	xor    %eax,%eax
  51c0c3:	nopl   0x0(%rax,%rax,1)
  51c0c8:	mov    %rax,%rcx
  51c0cb:	add    $0x1,%rax
  51c0cf:	shl    $0x6,%rcx
  51c0d3:	add    %rsi,%rcx
  51c0d6:	mov    0x38(%rcx),%rcx
  51c0da:	add    %rcx,%rdx
  51c0dd:	cmp    0xd8(%rbx),%rax
  51c0e4:	jbe    51c0c8 <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0xa8>
  51c0e6:	sub    %rdx,%r12
  51c0e9:	cmpb   $0x0,-0x28(%rbp)
  51c0ed:	jne    51c128 <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0x108>
  51c0ef:	mov    0x9d0(%rbx),%rdi
  51c0f6:	mov    (%rdi),%rax
  51c0f9:	callq  *0x38(%rax)
  51c0fc:	lea    (%rax,%r12,1),%rdx
  51c100:	mov    %rax,%rcx
  51c103:	mov    $0xffffffffffffffff,%rax
  51c10a:	not    %rcx
  51c10d:	cmp    %r12,%rcx
  51c110:	cmova  %rdx,%rax
  51c114:	add    $0x20,%rsp
  51c118:	pop    %rbx
  51c119:	pop    %r12
  51c11b:	pop    %r13
  51c11d:	pop    %r14
  51c11f:	pop    %rbp
  51c120:	retq   
  51c121:	nopl   0x0(%rax)
  51c128:	mov    -0x30(%rbp),%rax
  51c12c:	test   %rax,%rax
  51c12f:	je     51c0ef <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0xcf>
  51c131:	movb   $0x0,(%rax)
  51c134:	jmp    51c0ef <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0xcf>
  51c136:	mov    $0x1,%edi
  51c13b:	callq  407cc0 <_ZSt20__throw_system_errori@plt>
  51c140:	cmpb   $0x0,-0x28(%rbp)
  51c144:	mov    %rax,%rbx
  51c147:	je     51c152 <_ZN7rocksdb8MemTable22ApproximateMemoryUsageEv+0x132>
  51c149:	lea    -0x30(%rbp),%rdi
  51c14d:	callq  51dd50 <_ZNSt11unique_lockIN7rocksdb9SpinMutexEE6unlockEv>
  51c152:	mov    %rbx,%rdi
  51c155:	callq  4088b0 <_Unwind_Resume@plt>
  51c15a:	nopw   0x0(%rax,%rax,1)
