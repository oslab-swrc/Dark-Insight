// TC_OUT selinux_status_policyload@@Base,0x18850,0x1885e,0x4(%rbp)
0000000000018830 <selinux_status_policyload@@Base>:
   18830:	push   %r12
   18832:	push   %rbp
   18833:	mov    0x20db16(%rip),%rbp        # 226350 <myprintf_compat@@Base+0x11a8>
   1883a:	push   %rbx
   1883b:	test   %rbp,%rbp
   1883e:	je     188a7 <selinux_status_policyload@@Base+0x77>
   18840:	cmp    $0xffffffffffffffff,%rbp
   18844:	jne    18855 <selinux_status_policyload@@Base+0x25>
   18846:	jmp    18896 <selinux_status_policyload@@Base+0x66>
   18848:	nopl   0x0(%rax,%rax,1)
   18850:	callq  5fc0 <_init@@Base+0x288>
   18855:	mov    0x4(%rbp),%ebx
   18858:	mfence 
   1885b:	test   $0x1,%bl
   1885e:	jne    18850 <selinux_status_policyload@@Base+0x20>
   18860:	mov    0x20dae9(%rip),%r12        # 226350 <myprintf_compat@@Base+0x11a8>
   18867:	mov    0xc(%r12),%ebp
   1886c:	jmp    18875 <selinux_status_policyload@@Base+0x45>
   1886e:	xchg   %ax,%ax
   18870:	callq  5fc0 <_init@@Base+0x288>
   18875:	mov    0x4(%r12),%edx
   1887a:	mfence 
   1887d:	test   $0x1,%dl
   18880:	jne    18870 <selinux_status_policyload@@Base+0x40>
   18882:	cmp    %ebx,%edx
   18884:	je     1888f <selinux_status_policyload@@Base+0x5f>
   18886:	mov    0x20dac3(%rip),%rbp        # 226350 <myprintf_compat@@Base+0x11a8>
   1888d:	jmp    18855 <selinux_status_policyload@@Base+0x25>
   1888f:	mov    %ebp,%eax
   18891:	pop    %rbx
   18892:	pop    %rbp
   18893:	pop    %r12
   18895:	retq   
   18896:	callq  6280 <_init@@Base+0x548>
   1889b:	test   %eax,%eax
   1889d:	js     1888f <selinux_status_policyload@@Base+0x5f>
   1889f:	mov    0x20da93(%rip),%eax        # 226338 <myprintf_compat@@Base+0x1190>
   188a5:	jmp    18891 <selinux_status_policyload@@Base+0x61>
   188a7:	callq  5da0 <_init@@Base+0x68>
   188ac:	movl   $0x16,(%rax)
   188b2:	mov    $0xffffffff,%eax
   188b7:	jmp    18891 <selinux_status_policyload@@Base+0x61>
   188b9:	nopl   0x0(%rax)
