// TC_OUT thread,0x400cc0,0x400cd9,0x0(%rdx)
// TC_OUT thread,0x400cf0,0x400d09,0x0(%rdx)
// TC_OUT thread,0x400d18,0x400d1e,0x0(%rdi)
// TC_OUT thread,0x400df0,0x400e09,0x0(%rdx)
// TC_OUT thread,0x400e20,0x400e39,0x0(%rdx)

ck_neutral:     file format elf64-x86-64


Disassembly of section .init:

0000000000400700 <_init>:
  400700:	sub    $0x8,%rsp
  400704:	mov    0x2018e5(%rip),%rax        # 601ff0 <_DYNAMIC+0x1e8>
  40070b:	test   %rax,%rax
  40070e:	je     400712 <_init+0x12>
  400710:	callq  *%rax
  400712:	add    $0x8,%rsp
  400716:	retq   

Disassembly of section .plt:

0000000000400720 <pthread_create@plt-0x10>:
  400720:	pushq  0x2018e2(%rip)        # 602008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400726:	jmpq   *0x2018e4(%rip)        # 602010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40072c:	nopl   0x0(%rax)

0000000000400730 <pthread_create@plt>:
  400730:	jmpq   *0x2018e2(%rip)        # 602018 <_GLOBAL_OFFSET_TABLE_+0x18>
  400736:	pushq  $0x0
  40073b:	jmpq   400720 <_init+0x20>

0000000000400740 <sched_setaffinity@plt>:
  400740:	jmpq   *0x2018da(%rip)        # 602020 <_GLOBAL_OFFSET_TABLE_+0x20>
  400746:	pushq  $0x1
  40074b:	jmpq   400720 <_init+0x20>

0000000000400750 <syscall@plt>:
  400750:	jmpq   *0x2018d2(%rip)        # 602028 <_GLOBAL_OFFSET_TABLE_+0x28>
  400756:	pushq  $0x2
  40075b:	jmpq   400720 <_init+0x20>

0000000000400760 <strtol@plt>:
  400760:	jmpq   *0x2018ca(%rip)        # 602030 <_GLOBAL_OFFSET_TABLE_+0x30>
  400766:	pushq  $0x3
  40076b:	jmpq   400720 <_init+0x20>

0000000000400770 <malloc@plt>:
  400770:	jmpq   *0x2018c2(%rip)        # 602038 <_GLOBAL_OFFSET_TABLE_+0x38>
  400776:	pushq  $0x4
  40077b:	jmpq   400720 <_init+0x20>

0000000000400780 <perror@plt>:
  400780:	jmpq   *0x2018ba(%rip)        # 602040 <_GLOBAL_OFFSET_TABLE_+0x40>
  400786:	pushq  $0x5
  40078b:	jmpq   400720 <_init+0x20>

0000000000400790 <pthread_join@plt>:
  400790:	jmpq   *0x2018b2(%rip)        # 602048 <_GLOBAL_OFFSET_TABLE_+0x48>
  400796:	pushq  $0x6
  40079b:	jmpq   400720 <_init+0x20>

00000000004007a0 <vfprintf@plt>:
  4007a0:	jmpq   *0x2018aa(%rip)        # 602050 <_GLOBAL_OFFSET_TABLE_+0x50>
  4007a6:	pushq  $0x7
  4007ab:	jmpq   400720 <_init+0x20>

00000000004007b0 <exit@plt>:
  4007b0:	jmpq   *0x2018a2(%rip)        # 602058 <_GLOBAL_OFFSET_TABLE_+0x58>
  4007b6:	pushq  $0x8
  4007bb:	jmpq   400720 <_init+0x20>

00000000004007c0 <fwrite@plt>:
  4007c0:	jmpq   *0x20189a(%rip)        # 602060 <_GLOBAL_OFFSET_TABLE_+0x60>
  4007c6:	pushq  $0x9
  4007cb:	jmpq   400720 <_init+0x20>

Disassembly of section .text:

00000000004007d0 <main>:
  4007d0:	push   %r15
  4007d2:	push   %r14
  4007d4:	push   %r13
  4007d6:	push   %r12
  4007d8:	push   %rbp
  4007d9:	push   %rbx
  4007da:	sub    $0x8,%rsp
  4007de:	cmp    $0x4,%edi
  4007e1:	jne    400a55 <main+0x285>
  4007e7:	mov    0x8(%rsi),%rdi
  4007eb:	mov    %rsi,%rbx
  4007ee:	mov    $0xa,%edx
  4007f3:	xor    %esi,%esi
  4007f5:	callq  400760 <strtol@plt>
  4007fa:	test   %eax,%eax
  4007fc:	mov    %rax,%rbp
  4007ff:	mov    %eax,0x201873(%rip)        # 602078 <n_cohorts>
  400805:	jle    400a47 <main+0x277>
  40080b:	mov    0x10(%rbx),%rdi
  40080f:	xor    %esi,%esi
  400811:	mov    $0xa,%edx
  400816:	callq  400760 <strtol@plt>
  40081b:	test   %eax,%eax
  40081d:	jle    400a39 <main+0x269>
  400823:	imul   %ebp,%eax
  400826:	mov    %eax,0x201860(%rip)        # 60208c <nthr>
  40082c:	cltq   
  40082e:	lea    0x0(,%rax,8),%rdi
  400836:	callq  400770 <malloc@plt>
  40083b:	test   %rax,%rax
  40083e:	mov    %rax,%r12
  400841:	je     400a2b <main+0x25b>
  400847:	mov    0x18(%rbx),%rdi
  40084b:	xor    %esi,%esi
  40084d:	mov    $0xa,%edx
  400852:	callq  400760 <strtol@plt>
  400857:	mov    0x20179a(%rip),%r13        # 601ff8 <_DYNAMIC+0x1f0>
  40085e:	lea    0x93b(%rip),%rdi        # 4011a0 <__dso_handle+0x1f8>
  400865:	mov    $0x13,%edx
  40086a:	mov    $0x1,%esi
  40086f:	mov    %eax,0x201823(%rip)        # 602098 <a>
  400875:	mov    0x0(%r13),%rcx
  400879:	callq  4007c0 <fwrite@plt>
  40087e:	movslq 0x2017f3(%rip),%rdi        # 602078 <n_cohorts>
  400885:	mov    %rdi,%rbx
  400888:	shl    $0x5,%rdi
  40088c:	callq  400770 <malloc@plt>
  400891:	test   %rax,%rax
  400894:	mov    %rax,0x2017e5(%rip)        # 602080 <cohorts>
  40089b:	je     400a1d <main+0x24d>
  4008a1:	test   %ebx,%ebx
  4008a3:	jle    400907 <main+0x137>
  4008a5:	mov    %rax,%rbx
  4008a8:	xor    %r15d,%r15d
  4008ab:	xor    %ebp,%ebp
  4008ad:	lea    0x2017d4(%rip),%r14        # 602088 <global_fas_lock>
  4008b4:	jmp    4008c7 <main+0xf7>
  4008b6:	nopw   %cs:0x0(%rax,%rax,1)
  4008c0:	mov    0x2017b9(%rip),%rbx        # 602080 <cohorts>
  4008c7:	mov    $0x4,%edi
  4008cc:	callq  400770 <malloc@plt>
  4008d1:	lea    (%rbx,%r15,1),%rdx
  4008d5:	mov    %r14,(%rdx)
  4008d8:	mov    %rax,0x8(%rdx)
  4008dc:	movl   $0x0,0x10(%rdx)
  4008e3:	movl   $0x0,0x14(%rdx)
  4008ea:	movl   $0x0,0x18(%rdx)
  4008f1:	movl   $0xa,0x1c(%rdx)
  4008f8:	add    $0x1,%ebp
  4008fb:	add    $0x20,%r15
  4008ff:	cmp    %ebp,0x201773(%rip)        # 602078 <n_cohorts>
  400905:	jg     4008c0 <main+0xf0>
  400907:	mov    0x0(%r13),%rcx
  40090b:	lea    0x8a2(%rip),%rdi        # 4011b4 <__dso_handle+0x20c>
  400912:	mov    $0x5,%edx
  400917:	mov    $0x1,%esi
  40091c:	xor    %ebx,%ebx
  40091e:	mov    %r12,%rbp
  400921:	lea    0x2f8(%rip),%r14        # 400c20 <thread>
  400928:	callq  4007c0 <fwrite@plt>
  40092d:	mov    0x0(%r13),%rcx
  400931:	lea    0x882(%rip),%rdi        # 4011ba <__dso_handle+0x212>
  400938:	mov    $0x13,%edx
  40093d:	mov    $0x1,%esi
  400942:	callq  4007c0 <fwrite@plt>
  400947:	mov    0x20173f(%rip),%edx        # 60208c <nthr>
  40094d:	test   %edx,%edx
  40094f:	jle    40097e <main+0x1ae>
  400951:	nopl   0x0(%rax)
  400958:	xor    %ecx,%ecx
  40095a:	xor    %esi,%esi
  40095c:	mov    %r14,%rdx
  40095f:	mov    %rbp,%rdi
  400962:	callq  400730 <pthread_create@plt>
  400967:	test   %eax,%eax
  400969:	jne    400a0d <main+0x23d>
  40096f:	add    $0x1,%ebx
  400972:	add    $0x8,%rbp
  400976:	cmp    %ebx,0x201710(%rip)        # 60208c <nthr>
  40097c:	jg     400958 <main+0x188>
  40097e:	mov    0x0(%r13),%rcx
  400982:	lea    0x82b(%rip),%rdi        # 4011b4 <__dso_handle+0x20c>
  400989:	mov    $0x5,%edx
  40098e:	mov    $0x1,%esi
  400993:	mov    $0x1,%ebx
  400998:	callq  4007c0 <fwrite@plt>
  40099d:	mov    0x0(%r13),%rcx
  4009a1:	lea    0x750(%rip),%rdi        # 4010f8 <__dso_handle+0x150>
  4009a8:	mov    $0x37,%edx
  4009ad:	mov    $0x1,%esi
  4009b2:	callq  4007c0 <fwrite@plt>
  4009b7:	mov    0x2016cf(%rip),%eax        # 60208c <nthr>
  4009bd:	test   %eax,%eax
  4009bf:	jle    4009e2 <main+0x212>
  4009c1:	nopl   0x0(%rax)
  4009c8:	mov    -0x8(%r12,%rbx,8),%rdi
  4009cd:	xor    %esi,%esi
  4009cf:	callq  400790 <pthread_join@plt>
  4009d4:	mov    %ebx,%eax
  4009d6:	add    $0x1,%rbx
  4009da:	cmp    %eax,0x2016ac(%rip)        # 60208c <nthr>
  4009e0:	jg     4009c8 <main+0x1f8>
  4009e2:	mov    0x0(%r13),%rcx
  4009e6:	lea    0x7e1(%rip),%rdi        # 4011ce <__dso_handle+0x226>
  4009ed:	mov    $0xe,%edx
  4009f2:	mov    $0x1,%esi
  4009f7:	callq  4007c0 <fwrite@plt>
  4009fc:	add    $0x8,%rsp
  400a00:	xor    %eax,%eax
  400a02:	pop    %rbx
  400a03:	pop    %rbp
  400a04:	pop    %r12
  400a06:	pop    %r13
  400a08:	pop    %r14
  400a0a:	pop    %r15
  400a0c:	retq   
  400a0d:	lea    0x71c(%rip),%rdi        # 401130 <__dso_handle+0x188>
  400a14:	mov    %ebx,%esi
  400a16:	xor    %eax,%eax
  400a18:	callq  400b70 <ck_error>
  400a1d:	lea    0x69c(%rip),%rdi        # 4010c0 <__dso_handle+0x118>
  400a24:	xor    %eax,%eax
  400a26:	callq  400b70 <ck_error>
  400a2b:	lea    0x65e(%rip),%rdi        # 401090 <__dso_handle+0xe8>
  400a32:	xor    %eax,%eax
  400a34:	callq  400b70 <ck_error>
  400a39:	lea    0x618(%rip),%rdi        # 401058 <__dso_handle+0xb0>
  400a40:	xor    %eax,%eax
  400a42:	callq  400b70 <ck_error>
  400a47:	lea    0x5d2(%rip),%rdi        # 401020 <__dso_handle+0x78>
  400a4e:	xor    %eax,%eax
  400a50:	callq  400b70 <ck_error>
  400a55:	lea    0x574(%rip),%rdi        # 400fd0 <__dso_handle+0x28>
  400a5c:	xor    %eax,%eax
  400a5e:	callq  400b70 <ck_error>
  400a63:	nopw   %cs:0x0(%rax,%rax,1)
  400a6d:	nopl   (%rax)

0000000000400a70 <_start>:
  400a70:	xor    %ebp,%ebp
  400a72:	mov    %rdx,%r9
  400a75:	pop    %rsi
  400a76:	mov    %rsp,%rdx
  400a79:	and    $0xfffffffffffffff0,%rsp
  400a7d:	push   %rax
  400a7e:	push   %rsp
  400a7f:	mov    $0x400f90,%r8
  400a86:	mov    $0x400f20,%rcx
  400a8d:	mov    $0x4007d0,%rdi
  400a94:	callq  *0x20154e(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  400a9a:	hlt    
  400a9b:	nopl   0x0(%rax,%rax,1)

0000000000400aa0 <deregister_tm_clones>:
  400aa0:	mov    $0x602077,%eax
  400aa5:	push   %rbp
  400aa6:	sub    $0x602070,%rax
  400aac:	cmp    $0xe,%rax
  400ab0:	mov    %rsp,%rbp
  400ab3:	jbe    400ad0 <deregister_tm_clones+0x30>
  400ab5:	mov    $0x0,%eax
  400aba:	test   %rax,%rax
  400abd:	je     400ad0 <deregister_tm_clones+0x30>
  400abf:	pop    %rbp
  400ac0:	mov    $0x602070,%edi
  400ac5:	jmpq   *%rax
  400ac7:	nopw   0x0(%rax,%rax,1)
  400ad0:	pop    %rbp
  400ad1:	retq   
  400ad2:	nopl   0x0(%rax)
  400ad6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400ae0 <register_tm_clones>:
  400ae0:	mov    $0x602070,%esi
  400ae5:	push   %rbp
  400ae6:	sub    $0x602070,%rsi
  400aed:	sar    $0x3,%rsi
  400af1:	mov    %rsp,%rbp
  400af4:	mov    %rsi,%rax
  400af7:	shr    $0x3f,%rax
  400afb:	add    %rax,%rsi
  400afe:	sar    %rsi
  400b01:	je     400b18 <register_tm_clones+0x38>
  400b03:	mov    $0x0,%eax
  400b08:	test   %rax,%rax
  400b0b:	je     400b18 <register_tm_clones+0x38>
  400b0d:	pop    %rbp
  400b0e:	mov    $0x602070,%edi
  400b13:	jmpq   *%rax
  400b15:	nopl   (%rax)
  400b18:	pop    %rbp
  400b19:	retq   
  400b1a:	nopw   0x0(%rax,%rax,1)

0000000000400b20 <__do_global_dtors_aux>:
  400b20:	cmpb   $0x0,0x201549(%rip)        # 602070 <__TMC_END__>
  400b27:	jne    400b3a <__do_global_dtors_aux+0x1a>
  400b29:	push   %rbp
  400b2a:	mov    %rsp,%rbp
  400b2d:	callq  400aa0 <deregister_tm_clones>
  400b32:	pop    %rbp
  400b33:	movb   $0x1,0x201536(%rip)        # 602070 <__TMC_END__>
  400b3a:	repz retq 
  400b3c:	nopl   0x0(%rax)

0000000000400b40 <frame_dummy>:
  400b40:	mov    $0x601e00,%edi
  400b45:	cmpq   $0x0,(%rdi)
  400b49:	jne    400b50 <frame_dummy+0x10>
  400b4b:	jmp    400ae0 <register_tm_clones>
  400b4d:	nopl   (%rax)
  400b50:	mov    $0x0,%eax
  400b55:	test   %rax,%rax
  400b58:	je     400b4b <frame_dummy+0xb>
  400b5a:	push   %rbp
  400b5b:	mov    %rsp,%rbp
  400b5e:	callq  *%rax
  400b60:	pop    %rbp
  400b61:	jmpq   400ae0 <register_tm_clones>
  400b66:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b70 <ck_error>:
  400b70:	sub    $0xd8,%rsp
  400b77:	test   %al,%al
  400b79:	mov    %rsi,0x28(%rsp)
  400b7e:	mov    %rdx,0x30(%rsp)
  400b83:	mov    %rcx,0x38(%rsp)
  400b88:	mov    %r8,0x40(%rsp)
  400b8d:	mov    %r9,0x48(%rsp)
  400b92:	je     400bcb <ck_error+0x5b>
  400b94:	movaps %xmm0,0x50(%rsp)
  400b99:	movaps %xmm1,0x60(%rsp)
  400b9e:	movaps %xmm2,0x70(%rsp)
  400ba3:	movaps %xmm3,0x80(%rsp)
  400bab:	movaps %xmm4,0x90(%rsp)
  400bb3:	movaps %xmm5,0xa0(%rsp)
  400bbb:	movaps %xmm6,0xb0(%rsp)
  400bc3:	movaps %xmm7,0xc0(%rsp)
  400bcb:	lea    0xe0(%rsp),%rax
  400bd3:	mov    %rdi,%rsi
  400bd6:	lea    0x8(%rsp),%rdx
  400bdb:	mov    %rax,0x10(%rsp)
  400be0:	lea    0x20(%rsp),%rax
  400be5:	movl   $0x8,0x8(%rsp)
  400bed:	movl   $0x30,0xc(%rsp)
  400bf5:	mov    %rax,0x18(%rsp)
  400bfa:	mov    0x2013f7(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400c01:	mov    (%rax),%rdi
  400c04:	callq  4007a0 <vfprintf@plt>
  400c09:	mov    $0x1,%edi
  400c0e:	callq  4007b0 <exit@plt>
  400c13:	nopl   (%rax)
  400c16:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400c20 <thread>:
  400c20:	push   %r12
  400c22:	push   %rbp
  400c23:	push   %rbx
  400c24:	add    $0xffffffffffffff80,%rsp
  400c28:	mov    0x20146a(%rip),%ebx        # 602098 <a>
  400c2e:	lock xadd %ebx,0x201466(%rip)        # 60209c <a+0x4>
  400c36:	xor    %eax,%eax
  400c38:	mov    $0x10,%ecx
  400c3d:	mov    %rsp,%rdi
  400c40:	rep stos %rax,%es:(%rdi)
  400c43:	mov    %ebx,%ecx
  400c45:	mov    $0x1,%eax
  400c4a:	mov    $0xba,%edi
  400c4f:	and    $0x3,%ecx
  400c52:	shl    %cl,%rax
  400c55:	mov    %rax,(%rsp)
  400c59:	xor    %eax,%eax
  400c5b:	callq  400750 <syscall@plt>
  400c60:	mov    %rsp,%rdx
  400c63:	mov    $0x80,%esi
  400c68:	mov    %eax,%edi
  400c6a:	callq  400740 <sched_setaffinity@plt>
  400c6f:	test   %eax,%eax
  400c71:	jne    400eb9 <thread+0x299>
  400c77:	lea    0x20141a(%rip),%rbp        # 602098 <a>
  400c7e:	mov    %ebx,%eax
  400c80:	xor    %edx,%edx
  400c82:	lea    0x2013f3(%rip),%rdi        # 60207c <rw_cohort>
  400c89:	mov    $0xf4240,%r9d
  400c8f:	mov    $0x1,%ecx
  400c94:	divl   0x0(%rbp)
  400c97:	xor    %edx,%edx
  400c99:	divl   0x2013d9(%rip)        # 602078 <n_cohorts>
  400c9f:	mov    %edx,%esi
  400ca1:	shl    $0x5,%rsi
  400ca5:	add    0x2013d4(%rip),%rsi        # 602080 <cohorts>
  400cac:	lea    0x14(%rsi),%r8
  400cb0:	lock incl (%r8)
  400cb4:	mov    0x8(%rsi),%rdx
  400cb8:	nopl   0x0(%rax,%rax,1)
  400cc0:	mov    %ecx,%eax
  400cc2:	xchg   %eax,(%rdx)
  400cc4:	cmp    $0x1,%eax
  400cc7:	jne    400cdb <thread+0xbb>
  400cc9:	nopl   0x0(%rax)
  400cd0:	mov    (%rdx),%eax
  400cd2:	cmp    $0x1,%eax
  400cd5:	jne    400cc0 <thread+0xa0>
  400cd7:	pause  
  400cd9:	jmp    400cd0 <thread+0xb0>
  400cdb:	lock decl (%r8)
  400cdf:	mov    0x10(%rsi),%edx
  400ce2:	test   %edx,%edx
  400ce4:	jne    400d0b <thread+0xeb>
  400ce6:	mov    (%rsi),%rdx
  400ce9:	nopl   0x0(%rax)
  400cf0:	mov    %ecx,%eax
  400cf2:	xchg   %eax,(%rdx)
  400cf4:	cmp    $0x1,%eax
  400cf7:	jne    400d0b <thread+0xeb>
  400cf9:	nopl   0x0(%rax)
  400d00:	mov    (%rdx),%eax
  400d02:	cmp    $0x1,%eax
  400d05:	jne    400cf0 <thread+0xd0>
  400d07:	pause  
  400d09:	jmp    400d00 <thread+0xe0>
  400d0b:	addl   $0x1,0x18(%rsi)
  400d0f:	mov    (%rdi),%eax
  400d11:	test   %eax,%eax
  400d13:	je     400d20 <thread+0x100>
  400d15:	nopl   (%rax)
  400d18:	pause  
  400d1a:	mov    (%rdi),%eax
  400d1c:	test   %eax,%eax
  400d1e:	jne    400d18 <thread+0xf8>
  400d20:	mov    0x20136a(%rip),%edx        # 602090 <locked>
  400d26:	test   %edx,%edx
  400d28:	jne    400f08 <thread+0x2e8>
  400d2e:	lock incl 0x20135b(%rip)        # 602090 <locked>
  400d35:	lock incl 0x201354(%rip)        # 602090 <locked>
  400d3c:	lock incl 0x20134d(%rip)        # 602090 <locked>
  400d43:	lock incl 0x201346(%rip)        # 602090 <locked>
  400d4a:	lock incl 0x20133f(%rip)        # 602090 <locked>
  400d51:	lock incl 0x201338(%rip)        # 602090 <locked>
  400d58:	lock incl 0x201331(%rip)        # 602090 <locked>
  400d5f:	lock incl 0x20132a(%rip)        # 602090 <locked>
  400d66:	mov    0x201324(%rip),%edx        # 602090 <locked>
  400d6c:	cmp    $0x8,%edx
  400d6f:	jne    400ef5 <thread+0x2d5>
  400d75:	lock decl 0x201314(%rip)        # 602090 <locked>
  400d7c:	lock decl 0x20130d(%rip)        # 602090 <locked>
  400d83:	lock decl 0x201306(%rip)        # 602090 <locked>
  400d8a:	lock decl 0x2012ff(%rip)        # 602090 <locked>
  400d91:	lock decl 0x2012f8(%rip)        # 602090 <locked>
  400d98:	lock decl 0x2012f1(%rip)        # 602090 <locked>
  400d9f:	lock decl 0x2012ea(%rip)        # 602090 <locked>
  400da6:	lock decl 0x2012e3(%rip)        # 602090 <locked>
  400dad:	mov    0x2012dd(%rip),%edx        # 602090 <locked>
  400db3:	test   %edx,%edx
  400db5:	jne    400ee2 <thread+0x2c2>
  400dbb:	mov    (%r8),%eax
  400dbe:	test   %eax,%eax
  400dc0:	je     400e94 <thread+0x274>
  400dc6:	mov    0x1c(%rsi),%eax
  400dc9:	cmp    %eax,0x18(%rsi)
  400dcc:	jae    400e94 <thread+0x274>
  400dd2:	movl   $0x1,0x10(%rsi)
  400dd9:	mov    0x8(%rsi),%rax
  400ddd:	movl   $0x0,(%rax)
  400de3:	lock incl (%r8)
  400de7:	mov    0x8(%rsi),%rdx
  400deb:	nopl   0x0(%rax,%rax,1)
  400df0:	mov    %ecx,%eax
  400df2:	xchg   %eax,(%rdx)
  400df4:	cmp    $0x1,%eax
  400df7:	jne    400e0b <thread+0x1eb>
  400df9:	nopl   0x0(%rax)
  400e00:	mov    (%rdx),%eax
  400e02:	cmp    $0x1,%eax
  400e05:	jne    400df0 <thread+0x1d0>
  400e07:	pause  
  400e09:	jmp    400e00 <thread+0x1e0>
  400e0b:	lock decl (%r8)
  400e0f:	mov    0x10(%rsi),%eax
  400e12:	test   %eax,%eax
  400e14:	jne    400e3b <thread+0x21b>
  400e16:	mov    (%rsi),%rdx
  400e19:	nopl   0x0(%rax)
  400e20:	mov    %ecx,%eax
  400e22:	xchg   %eax,(%rdx)
  400e24:	cmp    $0x1,%eax
  400e27:	jne    400e3b <thread+0x21b>
  400e29:	nopl   0x0(%rax)
  400e30:	mov    (%rdx),%eax
  400e32:	cmp    $0x1,%eax
  400e35:	jne    400e20 <thread+0x200>
  400e37:	pause  
  400e39:	jmp    400e30 <thread+0x210>
  400e3b:	addl   $0x1,0x18(%rsi)
  400e3f:	lock incl (%rdi)
  400e42:	mov    (%r8),%eax
  400e45:	test   %eax,%eax
  400e47:	je     400e51 <thread+0x231>
  400e49:	mov    0x1c(%rsi),%eax
  400e4c:	cmp    %eax,0x18(%rsi)
  400e4f:	jb     400eb0 <thread+0x290>
  400e51:	mov    (%rsi),%rax
  400e54:	movl   $0x0,(%rax)
  400e5a:	movl   $0x0,0x10(%rsi)
  400e61:	movl   $0x0,0x18(%rsi)
  400e68:	mov    0x8(%rsi),%rax
  400e6c:	movl   $0x0,(%rax)
  400e72:	mov    0x201218(%rip),%edx        # 602090 <locked>
  400e78:	test   %edx,%edx
  400e7a:	jne    400ecf <thread+0x2af>
  400e7c:	lock decl (%rdi)
  400e7f:	sub    $0x1,%r9d
  400e83:	jne    400cb0 <thread+0x90>
  400e89:	sub    $0xffffffffffffff80,%rsp
  400e8d:	xor    %eax,%eax
  400e8f:	pop    %rbx
  400e90:	pop    %rbp
  400e91:	pop    %r12
  400e93:	retq   
  400e94:	mov    (%rsi),%rax
  400e97:	movl   $0x0,(%rax)
  400e9d:	movl   $0x0,0x10(%rsi)
  400ea4:	movl   $0x0,0x18(%rsi)
  400eab:	jmpq   400dd9 <thread+0x1b9>
  400eb0:	movl   $0x1,0x10(%rsi)
  400eb7:	jmp    400e68 <thread+0x248>
  400eb9:	lea    0xf0(%rip),%rdi        # 400fb0 <__dso_handle+0x8>
  400ec0:	callq  400780 <perror@plt>
  400ec5:	mov    $0x1,%edi
  400eca:	callq  4007b0 <exit@plt>
  400ecf:	lea    0x2b2(%rip),%rdi        # 401188 <__dso_handle+0x1e0>
  400ed6:	mov    $0x8e,%esi
  400edb:	xor    %eax,%eax
  400edd:	callq  400b70 <ck_error>
  400ee2:	lea    0x26f(%rip),%rdi        # 401158 <__dso_handle+0x1b0>
  400ee9:	mov    $0x85,%esi
  400eee:	xor    %eax,%eax
  400ef0:	callq  400b70 <ck_error>
  400ef5:	lea    0x274(%rip),%rdi        # 401170 <__dso_handle+0x1c8>
  400efc:	mov    $0x77,%esi
  400f01:	xor    %eax,%eax
  400f03:	callq  400b70 <ck_error>
  400f08:	lea    0x249(%rip),%rdi        # 401158 <__dso_handle+0x1b0>
  400f0f:	mov    $0x69,%esi
  400f14:	xor    %eax,%eax
  400f16:	callq  400b70 <ck_error>
  400f1b:	nopl   0x0(%rax,%rax,1)

0000000000400f20 <__libc_csu_init>:
  400f20:	push   %r15
  400f22:	push   %r14
  400f24:	mov    %edi,%r15d
  400f27:	push   %r13
  400f29:	push   %r12
  400f2b:	lea    0x200ebe(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400f32:	push   %rbp
  400f33:	lea    0x200ebe(%rip),%rbp        # 601df8 <__init_array_end>
  400f3a:	push   %rbx
  400f3b:	mov    %rsi,%r14
  400f3e:	mov    %rdx,%r13
  400f41:	sub    %r12,%rbp
  400f44:	sub    $0x8,%rsp
  400f48:	sar    $0x3,%rbp
  400f4c:	callq  400700 <_init>
  400f51:	test   %rbp,%rbp
  400f54:	je     400f76 <__libc_csu_init+0x56>
  400f56:	xor    %ebx,%ebx
  400f58:	nopl   0x0(%rax,%rax,1)
  400f60:	mov    %r13,%rdx
  400f63:	mov    %r14,%rsi
  400f66:	mov    %r15d,%edi
  400f69:	callq  *(%r12,%rbx,8)
  400f6d:	add    $0x1,%rbx
  400f71:	cmp    %rbx,%rbp
  400f74:	jne    400f60 <__libc_csu_init+0x40>
  400f76:	add    $0x8,%rsp
  400f7a:	pop    %rbx
  400f7b:	pop    %rbp
  400f7c:	pop    %r12
  400f7e:	pop    %r13
  400f80:	pop    %r14
  400f82:	pop    %r15
  400f84:	retq   
  400f85:	nop
  400f86:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400f90 <__libc_csu_fini>:
  400f90:	repz retq 

Disassembly of section .fini:

0000000000400f94 <_fini>:
  400f94:	sub    $0x8,%rsp
  400f98:	add    $0x8,%rsp
  400f9c:	retq   
