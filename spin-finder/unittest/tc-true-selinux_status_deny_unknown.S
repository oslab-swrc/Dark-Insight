// TC_OUT selinux_status_deny_unknown@@Base,0x188e0,0x188ee,0x4(%rbp)
// TC_OUT selinux_status_deny_unknown@@Base,0x188e5,0x188fb,0x4(%rbp),0x4(0x0(0x226350))
// TC_OUT selinux_status_deny_unknown@@Base,0x18900,0x1891a,0x4(%rbp),0x4(0x0(0x226350))
00000000000188c0 <selinux_status_deny_unknown@@Base>:
   188c0:	push   %r12
   188c2:	push   %rbp
   188c3:	mov    0x20da86(%rip),%rbp        # 226350 <myprintf_compat@@Base+0x11a8>
   188ca:	push   %rbx
   188cb:	test   %rbp,%rbp
   188ce:	je     18932 <selinux_status_deny_unknown@@Base+0x72>
   188d0:	cmp    $0xffffffffffffffff,%rbp
   188d4:	jne    188e5 <selinux_status_deny_unknown@@Base+0x25>
   188d6:	jmp    18929 <selinux_status_deny_unknown@@Base+0x69>
   188d8:	nopl   0x0(%rax,%rax,1)
   188e0:	callq  5fc0 <_init@@Base+0x288>
   188e5:	mov    0x4(%rbp),%ebx
   188e8:	mfence 
   188eb:	test   $0x1,%bl
   188ee:	jne    188e0 <selinux_status_deny_unknown@@Base+0x20>
   188f0:	mov    0x20da59(%rip),%rbp        # 226350 <myprintf_compat@@Base+0x11a8>
   188f7:	mov    0x10(%rbp),%r12d
   188fb:	jmp    18905 <selinux_status_deny_unknown@@Base+0x45>
   188fd:	nopl   (%rax)
   18900:	callq  5fc0 <_init@@Base+0x288>
   18905:	mov    0x4(%rbp),%eax
   18908:	mfence 
   1890b:	test   $0x1,%al
   1890d:	jne    18900 <selinux_status_deny_unknown@@Base+0x40>
   1890f:	cmp    %ebx,%eax
   18911:	je     1891c <selinux_status_deny_unknown@@Base+0x5c>
   18913:	mov    0x20da36(%rip),%rbp        # 226350 <myprintf_compat@@Base+0x11a8>
   1891a:	jmp    188e5 <selinux_status_deny_unknown@@Base+0x25>
   1891c:	xor    %eax,%eax
   1891e:	test   %r12d,%r12d
   18921:	setne  %al
   18924:	pop    %rbx
   18925:	pop    %rbp
   18926:	pop    %r12
   18928:	retq   
   18929:	pop    %rbx
   1892a:	pop    %rbp
   1892b:	pop    %r12
   1892d:	jmpq   5ee0 <_init@@Base+0x1a8>
   18932:	callq  5da0 <_init@@Base+0x68>
   18937:	movl   $0x16,(%rax)
   1893d:	mov    $0xffffffff,%eax
   18942:	jmp    18924 <selinux_status_deny_unknown@@Base+0x64>
   18944:	xchg   %ax,%ax
   18946:	nopw   %cs:0x0(%rax,%rax,1)
