// TC_OUT thread,0x400be8,0x400bef,0x0(%rcx)
// TC_OUT thread,0x400d60,0x400d67,0x0(%rdx)
ck_clh:     file format elf64-x86-64


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
  4007eb:	jne    400988 <main+0x1a8>
  4007f1:	mov    0x8(%rsi),%rdi
  4007f5:	mov    %rsi,%rbx
  4007f8:	mov    $0xa,%edx
  4007fd:	xor    %esi,%esi
  4007ff:	callq  400770 <strtol@plt>
  400804:	cltq   
  400806:	test   %rax,%rax
  400809:	mov    %rax,0x2018b8(%rip)        # 6020c8 <nthr>
  400810:	je     40097c <main+0x19c>
  400816:	mov    $0x40,%edi
  40081b:	callq  400780 <malloc@plt>
  400820:	movq   $0x0,0x8(%rax)
  400828:	movl   $0x0,(%rax)
  40082e:	mov    %rax,0x20188b(%rip)        # 6020c0 <lock>
  400835:	mov    0x20188c(%rip),%rax        # 6020c8 <nthr>
  40083c:	lea    0x0(,%rax,8),%rdi
  400844:	callq  400780 <malloc@plt>
  400849:	test   %rax,%rax
  40084c:	mov    %rax,%r12
  40084f:	je     40096e <main+0x18e>
  400855:	mov    0x10(%rbx),%rdi
  400859:	xor    %esi,%esi
  40085b:	mov    $0xa,%edx
  400860:	xor    %ebx,%ebx
  400862:	mov    %r12,%rbp
  400865:	lea    0x2e4(%rip),%r14        # 400b50 <thread>
  40086c:	callq  400770 <strtol@plt>
  400871:	mov    0x201780(%rip),%r13        # 601ff8 <_DYNAMIC+0x200>
  400878:	lea    0x701(%rip),%rdi        # 400f80 <__dso_handle+0x118>
  40087f:	mov    $0x26,%edx
  400884:	mov    $0x1,%esi
  400889:	mov    %eax,0x201849(%rip)        # 6020d8 <a>
  40088f:	movl   $0x0,0x201843(%rip)        # 6020dc <a+0x4>
  400899:	mov    0x0(%r13),%rcx
  40089d:	callq  4007d0 <fwrite@plt>
  4008a2:	cmpq   $0x0,0x20181e(%rip)        # 6020c8 <nthr>
  4008aa:	je     4008d8 <main+0xf8>
  4008ac:	nopl   0x0(%rax)
  4008b0:	xor    %ecx,%ecx
  4008b2:	xor    %esi,%esi
  4008b4:	mov    %r14,%rdx
  4008b7:	mov    %rbp,%rdi
  4008ba:	callq  400740 <pthread_create@plt>
  4008bf:	test   %eax,%eax
  4008c1:	jne    40095d <main+0x17d>
  4008c7:	add    $0x1,%rbx
  4008cb:	add    $0x8,%rbp
  4008cf:	cmp    %rbx,0x2017f2(%rip)        # 6020c8 <nthr>
  4008d6:	ja     4008b0 <main+0xd0>
  4008d8:	mov    0x0(%r13),%rcx
  4008dc:	lea    0x741(%rip),%rdi        # 401024 <__dso_handle+0x1bc>
  4008e3:	mov    $0x5,%edx
  4008e8:	mov    $0x1,%esi
  4008ed:	xor    %ebx,%ebx
  4008ef:	callq  4007d0 <fwrite@plt>
  4008f4:	mov    0x0(%r13),%rcx
  4008f8:	lea    0x6a9(%rip),%rdi        # 400fa8 <__dso_handle+0x140>
  4008ff:	mov    $0x37,%edx
  400904:	mov    $0x1,%esi
  400909:	callq  4007d0 <fwrite@plt>
  40090e:	cmpq   $0x0,0x2017b2(%rip)        # 6020c8 <nthr>
  400916:	je     400938 <main+0x158>
  400918:	nopl   0x0(%rax,%rax,1)
  400920:	mov    (%r12,%rbx,8),%rdi
  400924:	xor    %esi,%esi
  400926:	add    $0x1,%rbx
  40092a:	callq  4007a0 <pthread_join@plt>
  40092f:	cmp    %rbx,0x201792(%rip)        # 6020c8 <nthr>
  400936:	ja     400920 <main+0x140>
  400938:	mov    0x0(%r13),%rcx
  40093c:	lea    0x6e7(%rip),%rdi        # 40102a <__dso_handle+0x1c2>
  400943:	mov    $0xe,%edx
  400948:	mov    $0x1,%esi
  40094d:	callq  4007d0 <fwrite@plt>
  400952:	pop    %rbx
  400953:	xor    %eax,%eax
  400955:	pop    %rbp
  400956:	pop    %r12
  400958:	pop    %r13
  40095a:	pop    %r14
  40095c:	retq   
  40095d:	lea    0x67c(%rip),%rdi        # 400fe0 <__dso_handle+0x178>
  400964:	mov    %rbx,%rsi
  400967:	xor    %eax,%eax
  400969:	callq  400aa0 <ck_error>
  40096e:	lea    0x5db(%rip),%rdi        # 400f50 <__dso_handle+0xe8>
  400975:	xor    %eax,%eax
  400977:	callq  400aa0 <ck_error>
  40097c:	lea    0x595(%rip),%rdi        # 400f18 <__dso_handle+0xb0>
  400983:	callq  400aa0 <ck_error>
  400988:	lea    0x551(%rip),%rdi        # 400ee0 <__dso_handle+0x78>
  40098f:	xor    %eax,%eax
  400991:	callq  400aa0 <ck_error>
  400996:	nopw   %cs:0x0(%rax,%rax,1)

00000000004009a0 <_start>:
  4009a0:	xor    %ebp,%ebp
  4009a2:	mov    %rdx,%r9
  4009a5:	pop    %rsi
  4009a6:	mov    %rsp,%rdx
  4009a9:	and    $0xfffffffffffffff0,%rsp
  4009ad:	push   %rax
  4009ae:	push   %rsp
  4009af:	mov    $0x400e50,%r8
  4009b6:	mov    $0x400de0,%rcx
  4009bd:	mov    $0x4007e0,%rdi
  4009c4:	callq  *0x20161e(%rip)        # 601fe8 <_DYNAMIC+0x1f0>
  4009ca:	hlt    
  4009cb:	nopl   0x0(%rax,%rax,1)

00000000004009d0 <deregister_tm_clones>:
  4009d0:	mov    $0x602077,%eax
  4009d5:	push   %rbp
  4009d6:	sub    $0x602070,%rax
  4009dc:	cmp    $0xe,%rax
  4009e0:	mov    %rsp,%rbp
  4009e3:	jbe    400a00 <deregister_tm_clones+0x30>
  4009e5:	mov    $0x0,%eax
  4009ea:	test   %rax,%rax
  4009ed:	je     400a00 <deregister_tm_clones+0x30>
  4009ef:	pop    %rbp
  4009f0:	mov    $0x602070,%edi
  4009f5:	jmpq   *%rax
  4009f7:	nopw   0x0(%rax,%rax,1)
  400a00:	pop    %rbp
  400a01:	retq   
  400a02:	nopl   0x0(%rax)
  400a06:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a10 <register_tm_clones>:
  400a10:	mov    $0x602070,%esi
  400a15:	push   %rbp
  400a16:	sub    $0x602070,%rsi
  400a1d:	sar    $0x3,%rsi
  400a21:	mov    %rsp,%rbp
  400a24:	mov    %rsi,%rax
  400a27:	shr    $0x3f,%rax
  400a2b:	add    %rax,%rsi
  400a2e:	sar    %rsi
  400a31:	je     400a48 <register_tm_clones+0x38>
  400a33:	mov    $0x0,%eax
  400a38:	test   %rax,%rax
  400a3b:	je     400a48 <register_tm_clones+0x38>
  400a3d:	pop    %rbp
  400a3e:	mov    $0x602070,%edi
  400a43:	jmpq   *%rax
  400a45:	nopl   (%rax)
  400a48:	pop    %rbp
  400a49:	retq   
  400a4a:	nopw   0x0(%rax,%rax,1)

0000000000400a50 <__do_global_dtors_aux>:
  400a50:	cmpb   $0x0,0x201629(%rip)        # 602080 <completed.6917>
  400a57:	jne    400a6a <__do_global_dtors_aux+0x1a>
  400a59:	push   %rbp
  400a5a:	mov    %rsp,%rbp
  400a5d:	callq  4009d0 <deregister_tm_clones>
  400a62:	pop    %rbp
  400a63:	movb   $0x1,0x201616(%rip)        # 602080 <completed.6917>
  400a6a:	repz retq 
  400a6c:	nopl   0x0(%rax)

0000000000400a70 <frame_dummy>:
  400a70:	mov    $0x601df0,%edi
  400a75:	cmpq   $0x0,(%rdi)
  400a79:	jne    400a80 <frame_dummy+0x10>
  400a7b:	jmp    400a10 <register_tm_clones>
  400a7d:	nopl   (%rax)
  400a80:	mov    $0x0,%eax
  400a85:	test   %rax,%rax
  400a88:	je     400a7b <frame_dummy+0xb>
  400a8a:	push   %rbp
  400a8b:	mov    %rsp,%rbp
  400a8e:	callq  *%rax
  400a90:	pop    %rbp
  400a91:	jmpq   400a10 <register_tm_clones>
  400a96:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400aa0 <ck_error>:
  400aa0:	sub    $0xd8,%rsp
  400aa7:	test   %al,%al
  400aa9:	mov    %rsi,0x28(%rsp)
  400aae:	mov    %rdx,0x30(%rsp)
  400ab3:	mov    %rcx,0x38(%rsp)
  400ab8:	mov    %r8,0x40(%rsp)
  400abd:	mov    %r9,0x48(%rsp)
  400ac2:	je     400afb <ck_error+0x5b>
  400ac4:	movaps %xmm0,0x50(%rsp)
  400ac9:	movaps %xmm1,0x60(%rsp)
  400ace:	movaps %xmm2,0x70(%rsp)
  400ad3:	movaps %xmm3,0x80(%rsp)
  400adb:	movaps %xmm4,0x90(%rsp)
  400ae3:	movaps %xmm5,0xa0(%rsp)
  400aeb:	movaps %xmm6,0xb0(%rsp)
  400af3:	movaps %xmm7,0xc0(%rsp)
  400afb:	lea    0xe0(%rsp),%rax
  400b03:	mov    %rdi,%rsi
  400b06:	lea    0x8(%rsp),%rdx
  400b0b:	mov    %rax,0x10(%rsp)
  400b10:	lea    0x20(%rsp),%rax
  400b15:	movl   $0x8,0x8(%rsp)
  400b1d:	movl   $0x30,0xc(%rsp)
  400b25:	mov    %rax,0x18(%rsp)
  400b2a:	mov    0x2014c7(%rip),%rax        # 601ff8 <_DYNAMIC+0x200>
  400b31:	mov    (%rax),%rdi
  400b34:	callq  4007b0 <vfprintf@plt>
  400b39:	mov    $0x1,%edi
  400b3e:	callq  4007c0 <exit@plt>
  400b43:	nopl   (%rax)
  400b46:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b50 <thread>:
  400b50:	push   %rbp
  400b51:	push   %rbx
  400b52:	mov    $0x40,%edi
  400b57:	sub    $0x88,%rsp
  400b5e:	callq  400780 <malloc@plt>
  400b63:	mov    0x20156f(%rip),%esi        # 6020d8 <a>
  400b69:	mov    %rax,%rbx
  400b6c:	lock xadd %esi,0x201568(%rip)        # 6020dc <a+0x4>
  400b74:	xor    %eax,%eax
  400b76:	mov    $0x10,%ecx
  400b7b:	mov    %rsp,%rdi
  400b7e:	rep stos %rax,%es:(%rdi)
  400b81:	mov    %esi,%ecx
  400b83:	mov    $0x1,%eax
  400b88:	mov    $0xba,%edi
  400b8d:	and    $0x3,%ecx
  400b90:	shl    %cl,%rax
  400b93:	mov    %rax,(%rsp)
  400b97:	xor    %eax,%eax
  400b99:	callq  400760 <syscall@plt>
  400b9e:	mov    %rsp,%rdx
  400ba1:	mov    $0x80,%esi
  400ba6:	mov    %eax,%edi
  400ba8:	callq  400750 <sched_setaffinity@plt>
  400bad:	test   %eax,%eax
  400baf:	jne    400d92 <thread+0x242>
  400bb5:	lea    0x201504(%rip),%r8        # 6020c0 <lock>
  400bbc:	mov    %rbx,%rax
  400bbf:	mov    $0xf4240,%edi
  400bc4:	nopl   0x0(%rax)
  400bc8:	movl   $0x1,(%rax)
  400bce:	mov    %rax,%rcx
  400bd1:	xchg   %rcx,0x2014e8(%rip)        # 6020c0 <lock>
  400bd8:	mov    %rcx,0x8(%rax)
  400bdc:	mov    (%rcx),%edx
  400bde:	cmp    $0x1,%edx
  400be1:	jne    400bf1 <thread+0xa1>
  400be3:	nopl   0x0(%rax,%rax,1)
  400be8:	pause  
  400bea:	mov    (%rcx),%edx
  400bec:	cmp    $0x1,%edx
  400bef:	je     400be8 <thread+0x98>
  400bf1:	mov    (%r8),%rdx
  400bf4:	mov    (%rdx),%edx
  400bf6:	test   %edx,%edx
  400bf8:	je     400da8 <thread+0x258>
  400bfe:	mov    0x2014cc(%rip),%ebx        # 6020d0 <locked>
  400c04:	lea    0x1(%rbx),%edx
  400c07:	mov    %edx,0x2014c3(%rip)        # 6020d0 <locked>
  400c0d:	mov    0x2014bd(%rip),%ebx        # 6020d0 <locked>
  400c13:	lea    0x1(%rbx),%edx
  400c16:	mov    %edx,0x2014b4(%rip)        # 6020d0 <locked>
  400c1c:	mov    0x2014ae(%rip),%ebx        # 6020d0 <locked>
  400c22:	lea    0x1(%rbx),%edx
  400c25:	mov    %edx,0x2014a5(%rip)        # 6020d0 <locked>
  400c2b:	mov    0x20149f(%rip),%esi        # 6020d0 <locked>
  400c31:	lea    0x1(%rsi),%edx
  400c34:	mov    %edx,0x201496(%rip)        # 6020d0 <locked>
  400c3a:	mov    0x201490(%rip),%ebx        # 6020d0 <locked>
  400c40:	lea    0x1(%rbx),%edx
  400c43:	mov    %edx,0x201487(%rip)        # 6020d0 <locked>
  400c49:	mov    0x201481(%rip),%esi        # 6020d0 <locked>
  400c4f:	lea    0x1(%rsi),%edx
  400c52:	mov    %edx,0x201478(%rip)        # 6020d0 <locked>
  400c58:	mov    0x201472(%rip),%ebx        # 6020d0 <locked>
  400c5e:	lea    0x1(%rbx),%edx
  400c61:	mov    %edx,0x201469(%rip)        # 6020d0 <locked>
  400c67:	mov    0x201463(%rip),%esi        # 6020d0 <locked>
  400c6d:	lea    0x1(%rsi),%edx
  400c70:	mov    %edx,0x20145a(%rip)        # 6020d0 <locked>
  400c76:	mov    0x201454(%rip),%ebx        # 6020d0 <locked>
  400c7c:	lea    0x1(%rbx),%edx
  400c7f:	mov    %edx,0x20144b(%rip)        # 6020d0 <locked>
  400c85:	mov    0x201445(%rip),%esi        # 6020d0 <locked>
  400c8b:	lea    0x1(%rsi),%edx
  400c8e:	mov    %edx,0x20143c(%rip)        # 6020d0 <locked>
  400c94:	mov    0x201436(%rip),%esi        # 6020d0 <locked>
  400c9a:	cmp    $0xa,%esi
  400c9d:	jne    400db6 <thread+0x266>
  400ca3:	mov    0x201427(%rip),%ebx        # 6020d0 <locked>
  400ca9:	lea    -0x1(%rbx),%edx
  400cac:	mov    %edx,0x20141e(%rip)        # 6020d0 <locked>
  400cb2:	mov    0x201418(%rip),%esi        # 6020d0 <locked>
  400cb8:	lea    -0x1(%rsi),%edx
  400cbb:	mov    %edx,0x20140f(%rip)        # 6020d0 <locked>
  400cc1:	mov    0x201409(%rip),%ebx        # 6020d0 <locked>
  400cc7:	lea    -0x1(%rbx),%edx
  400cca:	mov    %edx,0x201400(%rip)        # 6020d0 <locked>
  400cd0:	mov    0x2013fa(%rip),%esi        # 6020d0 <locked>
  400cd6:	lea    -0x1(%rsi),%edx
  400cd9:	mov    %edx,0x2013f1(%rip)        # 6020d0 <locked>
  400cdf:	mov    0x2013eb(%rip),%ebx        # 6020d0 <locked>
  400ce5:	lea    -0x1(%rbx),%edx
  400ce8:	mov    %edx,0x2013e2(%rip)        # 6020d0 <locked>
  400cee:	mov    0x2013dc(%rip),%esi        # 6020d0 <locked>
  400cf4:	lea    -0x1(%rsi),%edx
  400cf7:	mov    %edx,0x2013d3(%rip)        # 6020d0 <locked>
  400cfd:	mov    0x2013cd(%rip),%ebx        # 6020d0 <locked>
  400d03:	lea    -0x1(%rbx),%edx
  400d06:	mov    %edx,0x2013c4(%rip)        # 6020d0 <locked>
  400d0c:	mov    0x2013be(%rip),%esi        # 6020d0 <locked>
  400d12:	lea    -0x1(%rsi),%edx
  400d15:	mov    %edx,0x2013b5(%rip)        # 6020d0 <locked>
  400d1b:	mov    0x2013af(%rip),%ebx        # 6020d0 <locked>
  400d21:	lea    -0x1(%rbx),%edx
  400d24:	mov    %edx,0x2013a6(%rip)        # 6020d0 <locked>
  400d2a:	mov    0x2013a0(%rip),%esi        # 6020d0 <locked>
  400d30:	lea    -0x1(%rsi),%edx
  400d33:	mov    %edx,0x201397(%rip)        # 6020d0 <locked>
  400d39:	mov    0x8(%rax),%rcx
  400d3d:	movl   $0x0,(%rax)
  400d43:	movl   $0x1,(%rcx)
  400d49:	mov    %rcx,%rdx
  400d4c:	xchg   %rdx,0x20136d(%rip)        # 6020c0 <lock>
  400d53:	mov    %rdx,0x8(%rcx)
  400d57:	mov    (%rdx),%eax
  400d59:	cmp    $0x1,%eax
  400d5c:	jne    400d69 <thread+0x219>
  400d5e:	xchg   %ax,%ax
  400d60:	pause  
  400d62:	mov    (%rdx),%eax
  400d64:	cmp    $0x1,%eax
  400d67:	je     400d60 <thread+0x210>
  400d69:	mov    0x201361(%rip),%esi        # 6020d0 <locked>
  400d6f:	test   %esi,%esi
  400d71:	jne    400dc4 <thread+0x274>
  400d73:	mov    0x8(%rcx),%rax
  400d77:	movl   $0x0,(%rcx)
  400d7d:	sub    $0x1,%edi
  400d80:	jne    400bc8 <thread+0x78>
  400d86:	add    $0x88,%rsp
  400d8d:	xor    %eax,%eax
  400d8f:	pop    %rbx
  400d90:	pop    %rbp
  400d91:	retq   
  400d92:	lea    0xd7(%rip),%rdi        # 400e70 <__dso_handle+0x8>
  400d99:	callq  400790 <perror@plt>
  400d9e:	mov    $0x1,%edi
  400da3:	callq  4007c0 <exit@plt>
  400da8:	lea    0x259(%rip),%rdi        # 401008 <__dso_handle+0x1a0>
  400daf:	xor    %eax,%eax
  400db1:	callq  400aa0 <ck_error>
  400db6:	lea    0xd3(%rip),%rdi        # 400e90 <__dso_handle+0x28>
  400dbd:	xor    %eax,%eax
  400dbf:	callq  400aa0 <ck_error>
  400dc4:	lea    0xed(%rip),%rdi        # 400eb8 <__dso_handle+0x50>
  400dcb:	xor    %eax,%eax
  400dcd:	callq  400aa0 <ck_error>
  400dd2:	nopw   %cs:0x0(%rax,%rax,1)
  400ddc:	nopl   0x0(%rax)

0000000000400de0 <__libc_csu_init>:
  400de0:	push   %r15
  400de2:	push   %r14
  400de4:	mov    %edi,%r15d
  400de7:	push   %r13
  400de9:	push   %r12
  400deb:	lea    0x200fee(%rip),%r12        # 601de0 <__frame_dummy_init_array_entry>
  400df2:	push   %rbp
  400df3:	lea    0x200fee(%rip),%rbp        # 601de8 <__init_array_end>
  400dfa:	push   %rbx
  400dfb:	mov    %rsi,%r14
  400dfe:	mov    %rdx,%r13
  400e01:	sub    %r12,%rbp
  400e04:	sub    $0x8,%rsp
  400e08:	sar    $0x3,%rbp
  400e0c:	callq  400710 <_init>
  400e11:	test   %rbp,%rbp
  400e14:	je     400e36 <__libc_csu_init+0x56>
  400e16:	xor    %ebx,%ebx
  400e18:	nopl   0x0(%rax,%rax,1)
  400e20:	mov    %r13,%rdx
  400e23:	mov    %r14,%rsi
  400e26:	mov    %r15d,%edi
  400e29:	callq  *(%r12,%rbx,8)
  400e2d:	add    $0x1,%rbx
  400e31:	cmp    %rbx,%rbp
  400e34:	jne    400e20 <__libc_csu_init+0x40>
  400e36:	add    $0x8,%rsp
  400e3a:	pop    %rbx
  400e3b:	pop    %rbp
  400e3c:	pop    %r12
  400e3e:	pop    %r13
  400e40:	pop    %r14
  400e42:	pop    %r15
  400e44:	retq   
  400e45:	nop
  400e46:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400e50 <__libc_csu_fini>:
  400e50:	repz retq 

Disassembly of section .fini:

0000000000400e54 <_fini>:
  400e54:	sub    $0x8,%rsp
  400e58:	add    $0x8,%rsp
  400e5c:	retq   
