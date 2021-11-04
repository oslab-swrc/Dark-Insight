// TC_OUT selinux_status_getenforce@@Base,0x187c0,0x187ce,0x4(%rbp)
// TC_OUT selinux_status_getenforce@@Base,0x187c5,0x187db,0x4(%rbp),0x4(0x0(0x226350))
// TC_OUT selinux_status_getenforce@@Base,0x187e0,0x187fa,0x4(%rbp),0x4(0x0(0x226350))
00000000000187a0 <selinux_status_getenforce@@Base>:
   187a0:	push   %r12
   187a2:	push   %rbp
   187a3:	mov    0x20dba6(%rip),%rbp        # 226350 <myprintf_compat@@Base+0x11a8>
   187aa:	push   %rbx
   187ab:	test   %rbp,%rbp
   187ae:	je     1881a <selinux_status_getenforce@@Base+0x7a>
   187b0:	cmp    $0xffffffffffffffff,%rbp
   187b4:	jne    187c5 <selinux_status_getenforce@@Base+0x25>
   187b6:	jmp    18809 <selinux_status_getenforce@@Base+0x69>
   187b8:	nopl   0x0(%rax,%rax,1)
   187c0:	callq  5fc0 <_init@@Base+0x288>
   187c5:	mov    0x4(%rbp),%ebx
   187c8:	mfence 
   187cb:	test   $0x1,%bl
   187ce:	jne    187c0 <selinux_status_getenforce@@Base+0x20>
   187d0:	mov    0x20db79(%rip),%rbp        # 226350 <myprintf_compat@@Base+0x11a8>
   187d7:	mov    0x8(%rbp),%r12d
   187db:	jmp    187e5 <selinux_status_getenforce@@Base+0x45>
   187dd:	nopl   (%rax)
   187e0:	callq  5fc0 <_init@@Base+0x288>
   187e5:	mov    0x4(%rbp),%eax
   187e8:	mfence 
   187eb:	test   $0x1,%al
   187ed:	jne    187e0 <selinux_status_getenforce@@Base+0x40>
   187ef:	cmp    %ebx,%eax
   187f1:	je     187fc <selinux_status_getenforce@@Base+0x5c>
   187f3:	mov    0x20db56(%rip),%rbp        # 226350 <myprintf_compat@@Base+0x11a8>
   187fa:	jmp    187c5 <selinux_status_getenforce@@Base+0x25>
   187fc:	xor    %eax,%eax
   187fe:	test   %r12d,%r12d
   18801:	setne  %al
   18804:	pop    %rbx
   18805:	pop    %rbp
   18806:	pop    %r12
   18808:	retq   
   18809:	callq  6280 <_init@@Base+0x548>
   1880e:	test   %eax,%eax
   18810:	js     1882c <selinux_status_getenforce@@Base+0x8c>
   18812:	mov    0x20db24(%rip),%eax        # 22633c <myprintf_compat@@Base+0x1194>
   18818:	jmp    18804 <selinux_status_getenforce@@Base+0x64>
   1881a:	callq  5da0 <_init@@Base+0x68>
   1881f:	movl   $0x16,(%rax)
   18825:	mov    $0xffffffff,%eax
   1882a:	jmp    18804 <selinux_status_getenforce@@Base+0x64>
   1882c:	mov    %ebp,%eax
   1882e:	jmp    18804 <selinux_status_getenforce@@Base+0x64>

