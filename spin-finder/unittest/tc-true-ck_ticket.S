// TC_OUT thread,0x400bc0,0x400bc9,0x0(%rdx)
// TC_OUT thread,0x400bd0,0x400bf3,0x0(%rdx),0x0(0x6020c0)
// TC_OUT thread,0x400d60,0x400d69,0x0(%rdx)

ck_ticket:     file format elf64-x86-64


Disassembly of section .init:

0000000000400710 <_init>:
  400710:	sub    $0x8,%rsp
  400714:	mov    0x2018d5(%rip),%rax        # 601ff0 <_DYNAMIC+0x1f8>
  40071b:	test   %rax,%rax
  40071e:	je     400722 <_init+0x12>
  400720:	callq  *%rax
  400722:	add    $0x8,%rsp
  400726:	retq   

Disassembly of section .plt:

0000000000400730 <pthread_create@plt-0x10>:
  400730:	pushq  0x2018d2(%rip)        # 602008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400736:	jmpq   *0x2018d4(%rip)        # 602010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40073c:	nopl   0x0(%rax)

0000000000400740 <pthread_create@plt>:
  400740:	jmpq   *0x2018d2(%rip)        # 602018 <_GLOBAL_OFFSET_TABLE_+0x18>
  400746:	pushq  $0x0
  40074b:	jmpq   400730 <_init+0x20>

0000000000400750 <sched_setaffinity@plt>:
  400750:	jmpq   *0x2018ca(%rip)        # 602020 <_GLOBAL_OFFSET_TABLE_+0x20>
  400756:	pushq  $0x1
  40075b:	jmpq   400730 <_init+0x20>

0000000000400760 <syscall@plt>:
  400760:	jmpq   *0x2018c2(%rip)        # 602028 <_GLOBAL_OFFSET_TABLE_+0x28>
  400766:	pushq  $0x2
  40076b:	jmpq   400730 <_init+0x20>

0000000000400770 <strtol@plt>:
  400770:	jmpq   *0x2018ba(%rip)        # 602030 <_GLOBAL_OFFSET_TABLE_+0x30>
  400776:	pushq  $0x3
  40077b:	jmpq   400730 <_init+0x20>

0000000000400780 <malloc@plt>:
  400780:	jmpq   *0x2018b2(%rip)        # 602038 <_GLOBAL_OFFSET_TABLE_+0x38>
  400786:	pushq  $0x4
  40078b:	jmpq   400730 <_init+0x20>

0000000000400790 <perror@plt>:
  400790:	jmpq   *0x2018aa(%rip)        # 602040 <_GLOBAL_OFFSET_TABLE_+0x40>
  400796:	pushq  $0x5
  40079b:	jmpq   400730 <_init+0x20>

00000000004007a0 <pthread_join@plt>:
  4007a0:	jmpq   *0x2018a2(%rip)        # 602048 <_GLOBAL_OFFSET_TABLE_+0x48>
  4007a6:	pushq  $0x6
  4007ab:	jmpq   400730 <_init+0x20>

00000000004007b0 <vfprintf@plt>:
  4007b0:	jmpq   *0x20189a(%rip)        # 602050 <_GLOBAL_OFFSET_TABLE_+0x50>
  4007b6:	pushq  $0x7
  4007bb:	jmpq   400730 <_init+0x20>

00000000004007c0 <exit@plt>:
  4007c0:	jmpq   *0x201892(%rip)        # 602058 <_GLOBAL_OFFSET_TABLE_+0x58>
  4007c6:	pushq  $0x8
  4007cb:	jmpq   400730 <_init+0x20>

00000000004007d0 <fwrite@plt>:
  4007d0:	jmpq   *0x20188a(%rip)        # 602060 <_GLOBAL_OFFSET_TABLE_+0x60>
  4007d6:	pushq  $0x9
  4007db:	jmpq   400730 <_init+0x20>

Disassembly of section .text:

00000000004007e0 <main>:
  4007e0:	cmp    $0x3,%edi
  4007e3:	push   %r14
  4007e5:	push   %r13
  4007e7:	push   %r12
  4007e9:	push   %rbp
  4007ea:	push   %rbx
  4007eb:	jne    400968 <main+0x188>
  4007f1:	mov    0x8(%rsi),%rdi
  4007f5:	mov    %rsi,%rbx
  4007f8:	mov    $0xa,%edx
  4007fd:	xor    %esi,%esi
  4007ff:	callq  400770 <strtol@plt>
  400804:	cltq   
  400806:	test   %rax,%rax
  400809:	mov    %rax,0x2018b8(%rip)        # 6020c8 <nthr>
  400810:	je     40095c <main+0x17c>
  400816:	lea    0x0(,%rax,8),%rdi
  40081e:	callq  400780 <malloc@plt>
  400823:	test   %rax,%rax
  400826:	mov    %rax,%r12
  400829:	je     40094e <main+0x16e>
  40082f:	mov    0x10(%rbx),%rdi
  400833:	xor    %esi,%esi
  400835:	mov    $0xa,%edx
  40083a:	xor    %ebx,%ebx
  40083c:	mov    %r12,%rbp
  40083f:	lea    0x2ea(%rip),%r14        # 400b30 <thread>
  400846:	callq  400770 <strtol@plt>
  40084b:	mov    0x2017a6(%rip),%r13        # 601ff8 <_DYNAMIC+0x200>
  400852:	lea    0x717(%rip),%rdi        # 400f70 <__dso_handle+0x118>
  400859:	mov    $0x26,%edx
  40085e:	mov    $0x1,%esi
  400863:	mov    %eax,0x20186f(%rip)        # 6020d8 <a>
  400869:	movl   $0x0,0x201869(%rip)        # 6020dc <a+0x4>
  400873:	mov    0x0(%r13),%rcx
  400877:	callq  4007d0 <fwrite@plt>
  40087c:	cmpq   $0x0,0x201844(%rip)        # 6020c8 <nthr>
  400884:	je     4008b8 <main+0xd8>
  400886:	nopw   %cs:0x0(%rax,%rax,1)
  400890:	xor    %ecx,%ecx
  400892:	xor    %esi,%esi
  400894:	mov    %r14,%rdx
  400897:	mov    %rbp,%rdi
  40089a:	callq  400740 <pthread_create@plt>
  40089f:	test   %eax,%eax
  4008a1:	jne    40093d <main+0x15d>
  4008a7:	add    $0x1,%rbx
  4008ab:	add    $0x8,%rbp
  4008af:	cmp    %rbx,0x201812(%rip)        # 6020c8 <nthr>
  4008b6:	ja     400890 <main+0xb0>
  4008b8:	mov    0x0(%r13),%rcx
  4008bc:	lea    0x751(%rip),%rdi        # 401014 <__dso_handle+0x1bc>
  4008c3:	mov    $0x5,%edx
  4008c8:	mov    $0x1,%esi
  4008cd:	xor    %ebx,%ebx
  4008cf:	callq  4007d0 <fwrite@plt>
  4008d4:	mov    0x0(%r13),%rcx
  4008d8:	lea    0x6b9(%rip),%rdi        # 400f98 <__dso_handle+0x140>
  4008df:	mov    $0x37,%edx
  4008e4:	mov    $0x1,%esi
  4008e9:	callq  4007d0 <fwrite@plt>
  4008ee:	cmpq   $0x0,0x2017d2(%rip)        # 6020c8 <nthr>
  4008f6:	je     400918 <main+0x138>
  4008f8:	nopl   0x0(%rax,%rax,1)
  400900:	mov    (%r12,%rbx,8),%rdi
  400904:	xor    %esi,%esi
  400906:	add    $0x1,%rbx
  40090a:	callq  4007a0 <pthread_join@plt>
  40090f:	cmp    %rbx,0x2017b2(%rip)        # 6020c8 <nthr>
  400916:	ja     400900 <main+0x120>
  400918:	mov    0x0(%r13),%rcx
  40091c:	lea    0x6f7(%rip),%rdi        # 40101a <__dso_handle+0x1c2>
  400923:	mov    $0xe,%edx
  400928:	mov    $0x1,%esi
  40092d:	callq  4007d0 <fwrite@plt>
  400932:	pop    %rbx
  400933:	xor    %eax,%eax
  400935:	pop    %rbp
  400936:	pop    %r12
  400938:	pop    %r13
  40093a:	pop    %r14
  40093c:	retq   
  40093d:	lea    0x68c(%rip),%rdi        # 400fd0 <__dso_handle+0x178>
  400944:	mov    %rbx,%rsi
  400947:	xor    %eax,%eax
  400949:	callq  400a80 <ck_error>
  40094e:	lea    0x5eb(%rip),%rdi        # 400f40 <__dso_handle+0xe8>
  400955:	xor    %eax,%eax
  400957:	callq  400a80 <ck_error>
  40095c:	lea    0x5a5(%rip),%rdi        # 400f08 <__dso_handle+0xb0>
  400963:	callq  400a80 <ck_error>
  400968:	lea    0x561(%rip),%rdi        # 400ed0 <__dso_handle+0x78>
  40096f:	xor    %eax,%eax
  400971:	callq  400a80 <ck_error>
  400976:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400980 <_start>:
  400980:	xor    %ebp,%ebp
  400982:	mov    %rdx,%r9
  400985:	pop    %rsi
  400986:	mov    %rsp,%rdx
  400989:	and    $0xfffffffffffffff0,%rsp
  40098d:	push   %rax
  40098e:	push   %rsp
  40098f:	mov    $0x400e40,%r8
  400996:	mov    $0x400dd0,%rcx
  40099d:	mov    $0x4007e0,%rdi
  4009a4:	callq  *0x20163e(%rip)        # 601fe8 <_DYNAMIC+0x1f0>
  4009aa:	hlt    
  4009ab:	nopl   0x0(%rax,%rax,1)

00000000004009b0 <deregister_tm_clones>:
  4009b0:	mov    $0x602077,%eax
  4009b5:	push   %rbp
  4009b6:	sub    $0x602070,%rax
  4009bc:	cmp    $0xe,%rax
  4009c0:	mov    %rsp,%rbp
  4009c3:	jbe    4009e0 <deregister_tm_clones+0x30>
  4009c5:	mov    $0x0,%eax
  4009ca:	test   %rax,%rax
  4009cd:	je     4009e0 <deregister_tm_clones+0x30>
  4009cf:	pop    %rbp
  4009d0:	mov    $0x602070,%edi
  4009d5:	jmpq   *%rax
  4009d7:	nopw   0x0(%rax,%rax,1)
  4009e0:	pop    %rbp
  4009e1:	retq   
  4009e2:	nopl   0x0(%rax)
  4009e6:	nopw   %cs:0x0(%rax,%rax,1)

00000000004009f0 <register_tm_clones>:
  4009f0:	mov    $0x602070,%esi
  4009f5:	push   %rbp
  4009f6:	sub    $0x602070,%rsi
  4009fd:	sar    $0x3,%rsi
  400a01:	mov    %rsp,%rbp
  400a04:	mov    %rsi,%rax
  400a07:	shr    $0x3f,%rax
  400a0b:	add    %rax,%rsi
  400a0e:	sar    %rsi
  400a11:	je     400a28 <register_tm_clones+0x38>
  400a13:	mov    $0x0,%eax
  400a18:	test   %rax,%rax
  400a1b:	je     400a28 <register_tm_clones+0x38>
  400a1d:	pop    %rbp
  400a1e:	mov    $0x602070,%edi
  400a23:	jmpq   *%rax
  400a25:	nopl   (%rax)
  400a28:	pop    %rbp
  400a29:	retq   
  400a2a:	nopw   0x0(%rax,%rax,1)

0000000000400a30 <__do_global_dtors_aux>:
  400a30:	cmpb   $0x0,0x201649(%rip)        # 602080 <completed.6917>
  400a37:	jne    400a4a <__do_global_dtors_aux+0x1a>
  400a39:	push   %rbp
  400a3a:	mov    %rsp,%rbp
  400a3d:	callq  4009b0 <deregister_tm_clones>
  400a42:	pop    %rbp
  400a43:	movb   $0x1,0x201636(%rip)        # 602080 <completed.6917>
  400a4a:	repz retq 
  400a4c:	nopl   0x0(%rax)

0000000000400a50 <frame_dummy>:
  400a50:	mov    $0x601df0,%edi
  400a55:	cmpq   $0x0,(%rdi)
  400a59:	jne    400a60 <frame_dummy+0x10>
  400a5b:	jmp    4009f0 <register_tm_clones>
  400a5d:	nopl   (%rax)
  400a60:	mov    $0x0,%eax
  400a65:	test   %rax,%rax
  400a68:	je     400a5b <frame_dummy+0xb>
  400a6a:	push   %rbp
  400a6b:	mov    %rsp,%rbp
  400a6e:	callq  *%rax
  400a70:	pop    %rbp
  400a71:	jmpq   4009f0 <register_tm_clones>
  400a76:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a80 <ck_error>:
  400a80:	sub    $0xd8,%rsp
  400a87:	test   %al,%al
  400a89:	mov    %rsi,0x28(%rsp)
  400a8e:	mov    %rdx,0x30(%rsp)
  400a93:	mov    %rcx,0x38(%rsp)
  400a98:	mov    %r8,0x40(%rsp)
  400a9d:	mov    %r9,0x48(%rsp)
  400aa2:	je     400adb <ck_error+0x5b>
  400aa4:	movaps %xmm0,0x50(%rsp)
  400aa9:	movaps %xmm1,0x60(%rsp)
  400aae:	movaps %xmm2,0x70(%rsp)
  400ab3:	movaps %xmm3,0x80(%rsp)
  400abb:	movaps %xmm4,0x90(%rsp)
  400ac3:	movaps %xmm5,0xa0(%rsp)
  400acb:	movaps %xmm6,0xb0(%rsp)
  400ad3:	movaps %xmm7,0xc0(%rsp)
  400adb:	lea    0xe0(%rsp),%rax
  400ae3:	mov    %rdi,%rsi
  400ae6:	lea    0x8(%rsp),%rdx
  400aeb:	mov    %rax,0x10(%rsp)
  400af0:	lea    0x20(%rsp),%rax
  400af5:	movl   $0x8,0x8(%rsp)
  400afd:	movl   $0x30,0xc(%rsp)
  400b05:	mov    %rax,0x18(%rsp)
  400b0a:	mov    0x2014e7(%rip),%rax        # 601ff8 <_DYNAMIC+0x200>
  400b11:	mov    (%rax),%rdi
  400b14:	callq  4007b0 <vfprintf@plt>
  400b19:	mov    $0x1,%edi
  400b1e:	callq  4007c0 <exit@plt>
  400b23:	nopl   (%rax)
  400b26:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b30 <thread>:
  400b30:	push   %rbx
  400b31:	add    $0xffffffffffffff80,%rsp
  400b35:	mov    0x20159d(%rip),%esi        # 6020d8 <a>
  400b3b:	lock xadd %esi,0x201599(%rip)        # 6020dc <a+0x4>
  400b43:	xor    %eax,%eax
  400b45:	mov    $0x10,%ecx
  400b4a:	mov    %rsp,%rdi
  400b4d:	rep stos %rax,%es:(%rdi)
  400b50:	and    $0x3,%esi
  400b53:	mov    $0x1,%eax
  400b58:	mov    $0xba,%edi
  400b5d:	mov    %esi,%ecx
  400b5f:	shl    %cl,%rax
  400b62:	mov    %rax,(%rsp)
  400b66:	xor    %eax,%eax
  400b68:	callq  400760 <syscall@plt>
  400b6d:	mov    %rsp,%rdx
  400b70:	mov    $0x80,%esi
  400b75:	mov    %eax,%edi
  400b77:	callq  400750 <sched_setaffinity@plt>
  400b7c:	test   %eax,%eax
  400b7e:	jne    400d8d <thread+0x25d>
  400b84:	lea    0x201535(%rip),%rdx        # 6020c0 <lock>
  400b8b:	mov    $0xf423f,%edi
  400b90:	mov    $0x10000,%r8d
  400b96:	nopw   %cs:0x0(%rax,%rax,1)
  400ba0:	test   $0x1,%dil
  400ba4:	je     400bd2 <thread+0xa2>
  400ba6:	mov    %r8d,%eax
  400ba9:	lock xadd %eax,0x20150f(%rip)        # 6020c0 <lock>
  400bb1:	mov    %eax,%ecx
  400bb3:	movzwl %ax,%eax
  400bb6:	shr    $0x10,%ecx
  400bb9:	cmp    %ecx,%eax
  400bbb:	je     400bf5 <thread+0xc5>
  400bbd:	nopl   (%rax)
  400bc0:	pause  
  400bc2:	mov    (%rdx),%eax
  400bc4:	movzwl %ax,%eax
  400bc7:	cmp    %eax,%ecx
  400bc9:	jne    400bc0 <thread+0x90>
  400bcb:	jmp    400bf5 <thread+0xc5>
  400bcd:	nopl   (%rax)
  400bd0:	pause  
  400bd2:	mov    (%rdx),%eax
  400bd4:	mov    %eax,%ecx
  400bd6:	movzwl %ax,%esi
  400bd9:	shr    $0x10,%ecx
  400bdc:	cmp    %ecx,%esi
  400bde:	jne    400bd0 <thread+0xa0>
  400be0:	lea    0x10000(%rax),%ecx
  400be6:	lock cmpxchg %ecx,0x2014d2(%rip)        # 6020c0 <lock>
  400bee:	sete   %al
  400bf1:	test   %al,%al
  400bf3:	je     400bd0 <thread+0xa0>
  400bf5:	mov    (%rdx),%eax
  400bf7:	movzwl %ax,%ecx
  400bfa:	shr    $0x10,%eax
  400bfd:	cmp    %eax,%ecx
  400bff:	je     400da3 <thread+0x273>
  400c05:	mov    0x2014c5(%rip),%eax        # 6020d0 <locked>
  400c0b:	add    $0x1,%eax
  400c0e:	mov    %eax,0x2014bc(%rip)        # 6020d0 <locked>
  400c14:	mov    0x2014b6(%rip),%eax        # 6020d0 <locked>
  400c1a:	add    $0x1,%eax
  400c1d:	mov    %eax,0x2014ad(%rip)        # 6020d0 <locked>
  400c23:	mov    0x2014a7(%rip),%eax        # 6020d0 <locked>
  400c29:	add    $0x1,%eax
  400c2c:	mov    %eax,0x20149e(%rip)        # 6020d0 <locked>
  400c32:	mov    0x201498(%rip),%eax        # 6020d0 <locked>
  400c38:	add    $0x1,%eax
  400c3b:	mov    %eax,0x20148f(%rip)        # 6020d0 <locked>
  400c41:	mov    0x201489(%rip),%eax        # 6020d0 <locked>
  400c47:	add    $0x1,%eax
  400c4a:	mov    %eax,0x201480(%rip)        # 6020d0 <locked>
  400c50:	mov    0x20147a(%rip),%eax        # 6020d0 <locked>
  400c56:	add    $0x1,%eax
  400c59:	mov    %eax,0x201471(%rip)        # 6020d0 <locked>
  400c5f:	mov    0x20146b(%rip),%eax        # 6020d0 <locked>
  400c65:	add    $0x1,%eax
  400c68:	mov    %eax,0x201462(%rip)        # 6020d0 <locked>
  400c6e:	mov    0x20145c(%rip),%eax        # 6020d0 <locked>
  400c74:	add    $0x1,%eax
  400c77:	mov    %eax,0x201453(%rip)        # 6020d0 <locked>
  400c7d:	mov    0x20144d(%rip),%eax        # 6020d0 <locked>
  400c83:	add    $0x1,%eax
  400c86:	mov    %eax,0x201444(%rip)        # 6020d0 <locked>
  400c8c:	mov    0x20143e(%rip),%eax        # 6020d0 <locked>
  400c92:	add    $0x1,%eax
  400c95:	mov    %eax,0x201435(%rip)        # 6020d0 <locked>
  400c9b:	mov    0x20142f(%rip),%esi        # 6020d0 <locked>
  400ca1:	cmp    $0xa,%esi
  400ca4:	jne    400db1 <thread+0x281>
  400caa:	mov    0x201420(%rip),%eax        # 6020d0 <locked>
  400cb0:	sub    $0x1,%eax
  400cb3:	mov    %eax,0x201417(%rip)        # 6020d0 <locked>
  400cb9:	mov    0x201411(%rip),%eax        # 6020d0 <locked>
  400cbf:	sub    $0x1,%eax
  400cc2:	mov    %eax,0x201408(%rip)        # 6020d0 <locked>
  400cc8:	mov    0x201402(%rip),%eax        # 6020d0 <locked>
  400cce:	sub    $0x1,%eax
  400cd1:	mov    %eax,0x2013f9(%rip)        # 6020d0 <locked>
  400cd7:	mov    0x2013f3(%rip),%eax        # 6020d0 <locked>
  400cdd:	sub    $0x1,%eax
  400ce0:	mov    %eax,0x2013ea(%rip)        # 6020d0 <locked>
  400ce6:	mov    0x2013e4(%rip),%eax        # 6020d0 <locked>
  400cec:	sub    $0x1,%eax
  400cef:	mov    %eax,0x2013db(%rip)        # 6020d0 <locked>
  400cf5:	mov    0x2013d5(%rip),%eax        # 6020d0 <locked>
  400cfb:	sub    $0x1,%eax
  400cfe:	mov    %eax,0x2013cc(%rip)        # 6020d0 <locked>
  400d04:	mov    0x2013c6(%rip),%eax        # 6020d0 <locked>
  400d0a:	sub    $0x1,%eax
  400d0d:	mov    %eax,0x2013bd(%rip)        # 6020d0 <locked>
  400d13:	mov    0x2013b7(%rip),%eax        # 6020d0 <locked>
  400d19:	sub    $0x1,%eax
  400d1c:	mov    %eax,0x2013ae(%rip)        # 6020d0 <locked>
  400d22:	mov    0x2013a8(%rip),%eax        # 6020d0 <locked>
  400d28:	sub    $0x1,%eax
  400d2b:	mov    %eax,0x20139f(%rip)        # 6020d0 <locked>
  400d31:	mov    0x201399(%rip),%eax        # 6020d0 <locked>
  400d37:	sub    $0x1,%eax
  400d3a:	mov    %eax,0x201390(%rip)        # 6020d0 <locked>
  400d40:	lock incw (%rdx)
  400d44:	mov    %r8d,%eax
  400d47:	lock xadd %eax,0x201371(%rip)        # 6020c0 <lock>
  400d4f:	mov    %eax,%ecx
  400d51:	movzwl %ax,%eax
  400d54:	shr    $0x10,%ecx
  400d57:	cmp    %ecx,%eax
  400d59:	je     400d6b <thread+0x23b>
  400d5b:	nopl   0x0(%rax,%rax,1)
  400d60:	pause  
  400d62:	mov    (%rdx),%eax
  400d64:	movzwl %ax,%eax
  400d67:	cmp    %eax,%ecx
  400d69:	jne    400d60 <thread+0x230>
  400d6b:	mov    0x20135f(%rip),%esi        # 6020d0 <locked>
  400d71:	test   %esi,%esi
  400d73:	jne    400dbf <thread+0x28f>
  400d75:	lock incw (%rdx)
  400d79:	sub    $0x1,%edi
  400d7c:	cmp    $0xffffffff,%edi
  400d7f:	jne    400ba0 <thread+0x70>
  400d85:	sub    $0xffffffffffffff80,%rsp
  400d89:	xor    %eax,%eax
  400d8b:	pop    %rbx
  400d8c:	retq   
  400d8d:	lea    0xcc(%rip),%rdi        # 400e60 <__dso_handle+0x8>
  400d94:	callq  400790 <perror@plt>
  400d99:	mov    $0x1,%edi
  400d9e:	callq  4007c0 <exit@plt>
  400da3:	lea    0x24e(%rip),%rdi        # 400ff8 <__dso_handle+0x1a0>
  400daa:	xor    %eax,%eax
  400dac:	callq  400a80 <ck_error>
  400db1:	lea    0xc8(%rip),%rdi        # 400e80 <__dso_handle+0x28>
  400db8:	xor    %eax,%eax
  400dba:	callq  400a80 <ck_error>
  400dbf:	lea    0xe2(%rip),%rdi        # 400ea8 <__dso_handle+0x50>
  400dc6:	xor    %eax,%eax
  400dc8:	callq  400a80 <ck_error>
  400dcd:	nopl   (%rax)

0000000000400dd0 <__libc_csu_init>:
  400dd0:	push   %r15
  400dd2:	push   %r14
  400dd4:	mov    %edi,%r15d
  400dd7:	push   %r13
  400dd9:	push   %r12
  400ddb:	lea    0x200ffe(%rip),%r12        # 601de0 <__frame_dummy_init_array_entry>
  400de2:	push   %rbp
  400de3:	lea    0x200ffe(%rip),%rbp        # 601de8 <__init_array_end>
  400dea:	push   %rbx
  400deb:	mov    %rsi,%r14
  400dee:	mov    %rdx,%r13
  400df1:	sub    %r12,%rbp
  400df4:	sub    $0x8,%rsp
  400df8:	sar    $0x3,%rbp
  400dfc:	callq  400710 <_init>
  400e01:	test   %rbp,%rbp
  400e04:	je     400e26 <__libc_csu_init+0x56>
  400e06:	xor    %ebx,%ebx
  400e08:	nopl   0x0(%rax,%rax,1)
  400e10:	mov    %r13,%rdx
  400e13:	mov    %r14,%rsi
  400e16:	mov    %r15d,%edi
  400e19:	callq  *(%r12,%rbx,8)
  400e1d:	add    $0x1,%rbx
  400e21:	cmp    %rbx,%rbp
  400e24:	jne    400e10 <__libc_csu_init+0x40>
  400e26:	add    $0x8,%rsp
  400e2a:	pop    %rbx
  400e2b:	pop    %rbp
  400e2c:	pop    %r12
  400e2e:	pop    %r13
  400e30:	pop    %r14
  400e32:	pop    %r15
  400e34:	retq   
  400e35:	nop
  400e36:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400e40 <__libc_csu_fini>:
  400e40:	repz retq 

Disassembly of section .fini:

0000000000400e44 <_fini>:
  400e44:	sub    $0x8,%rsp
  400e48:	add    $0x8,%rsp
  400e4c:	retq   
