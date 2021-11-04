// TC_OUT thread,0x400c90,0x400c97,0x0(%rcx)
// TC_OUT thread,0x400e40,0x400e47,0x0(%rdx)
// TC_OUT thread,0x400e80,0x400e87,0x0(%rdx)
// TC_OUT thread,0x400ea0,0x400ea7,0x0(%rax)

ck_hclh:     file format elf64-x86-64


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
  4007eb:	jne    4009e8 <main+0x208>
  4007f1:	mov    0x8(%rsi),%rdi
  4007f5:	mov    %rsi,%rbx
  4007f8:	mov    $0xa,%edx
  4007fd:	xor    %esi,%esi
  4007ff:	callq  400770 <strtol@plt>
  400804:	cltq   
  400806:	test   %rax,%rax
  400809:	mov    %rax,0x2018f8(%rip)        # 602108 <nthr>
  400810:	je     4009dc <main+0x1fc>
  400816:	mov    $0x40,%edi
  40081b:	callq  400780 <malloc@plt>
  400820:	movq   $0x0,0x10(%rax)
  400828:	movl   $0x0,(%rax)
  40082e:	movl   $0x0,0x4(%rax)
  400835:	movl   $0xffffffff,0x8(%rax)
  40083c:	mov    %rax,0x2018bd(%rip)        # 602100 <glob_lock>
  400843:	mov    $0x40,%edi
  400848:	callq  400780 <malloc@plt>
  40084d:	movq   $0x0,0x10(%rax)
  400855:	movl   $0x0,(%rax)
  40085b:	movl   $0x0,0x4(%rax)
  400862:	movl   $0x0,0x8(%rax)
  400869:	mov    %rax,0x201850(%rip)        # 6020c0 <local_lock>
  400870:	mov    $0x40,%edi
  400875:	callq  400780 <malloc@plt>
  40087a:	movq   $0x0,0x10(%rax)
  400882:	movl   $0x0,(%rax)
  400888:	movl   $0x0,0x4(%rax)
  40088f:	movl   $0x1,0x8(%rax)
  400896:	mov    %rax,0x20182b(%rip)        # 6020c8 <local_lock+0x8>
  40089d:	mov    0x201864(%rip),%rax        # 602108 <nthr>
  4008a4:	lea    0x0(,%rax,8),%rdi
  4008ac:	callq  400780 <malloc@plt>
  4008b1:	test   %rax,%rax
  4008b4:	mov    %rax,%r12
  4008b7:	je     4009ce <main+0x1ee>
  4008bd:	mov    0x10(%rbx),%rdi
  4008c1:	xor    %esi,%esi
  4008c3:	mov    $0xa,%edx
  4008c8:	xor    %ebx,%ebx
  4008ca:	mov    %r12,%rbp
  4008cd:	lea    0x2dc(%rip),%r14        # 400bb0 <thread>
  4008d4:	callq  400770 <strtol@plt>
  4008d9:	mov    0x201718(%rip),%r13        # 601ff8 <_DYNAMIC+0x200>
  4008e0:	lea    0x7b9(%rip),%rdi        # 4010a0 <__dso_handle+0x118>
  4008e7:	mov    $0x26,%edx
  4008ec:	mov    $0x1,%esi
  4008f1:	mov    %eax,0x201821(%rip)        # 602118 <a>
  4008f7:	movl   $0x0,0x20181b(%rip)        # 60211c <a+0x4>
  400901:	mov    0x0(%r13),%rcx
  400905:	callq  4007d0 <fwrite@plt>
  40090a:	cmpq   $0x0,0x2017f6(%rip)        # 602108 <nthr>
  400912:	je     400940 <main+0x160>
  400914:	nopl   0x0(%rax)
  400918:	xor    %ecx,%ecx
  40091a:	xor    %esi,%esi
  40091c:	mov    %r14,%rdx
  40091f:	mov    %rbp,%rdi
  400922:	callq  400740 <pthread_create@plt>
  400927:	test   %eax,%eax
  400929:	jne    4009bd <main+0x1dd>
  40092f:	add    $0x1,%rbx
  400933:	add    $0x8,%rbp
  400937:	cmp    %rbx,0x2017ca(%rip)        # 602108 <nthr>
  40093e:	ja     400918 <main+0x138>
  400940:	mov    0x0(%r13),%rcx
  400944:	lea    0x7f9(%rip),%rdi        # 401144 <__dso_handle+0x1bc>
  40094b:	mov    $0x5,%edx
  400950:	mov    $0x1,%esi
  400955:	xor    %ebx,%ebx
  400957:	callq  4007d0 <fwrite@plt>
  40095c:	mov    0x0(%r13),%rcx
  400960:	lea    0x761(%rip),%rdi        # 4010c8 <__dso_handle+0x140>
  400967:	mov    $0x37,%edx
  40096c:	mov    $0x1,%esi
  400971:	callq  4007d0 <fwrite@plt>
  400976:	cmpq   $0x0,0x20178a(%rip)        # 602108 <nthr>
  40097e:	je     400998 <main+0x1b8>
  400980:	mov    (%r12,%rbx,8),%rdi
  400984:	xor    %esi,%esi
  400986:	add    $0x1,%rbx
  40098a:	callq  4007a0 <pthread_join@plt>
  40098f:	cmp    %rbx,0x201772(%rip)        # 602108 <nthr>
  400996:	ja     400980 <main+0x1a0>
  400998:	mov    0x0(%r13),%rcx
  40099c:	lea    0x7a7(%rip),%rdi        # 40114a <__dso_handle+0x1c2>
  4009a3:	mov    $0xe,%edx
  4009a8:	mov    $0x1,%esi
  4009ad:	callq  4007d0 <fwrite@plt>
  4009b2:	pop    %rbx
  4009b3:	xor    %eax,%eax
  4009b5:	pop    %rbp
  4009b6:	pop    %r12
  4009b8:	pop    %r13
  4009ba:	pop    %r14
  4009bc:	retq   
  4009bd:	lea    0x73c(%rip),%rdi        # 401100 <__dso_handle+0x178>
  4009c4:	mov    %rbx,%rsi
  4009c7:	xor    %eax,%eax
  4009c9:	callq  400b00 <ck_error>
  4009ce:	lea    0x69b(%rip),%rdi        # 401070 <__dso_handle+0xe8>
  4009d5:	xor    %eax,%eax
  4009d7:	callq  400b00 <ck_error>
  4009dc:	lea    0x655(%rip),%rdi        # 401038 <__dso_handle+0xb0>
  4009e3:	callq  400b00 <ck_error>
  4009e8:	lea    0x611(%rip),%rdi        # 401000 <__dso_handle+0x78>
  4009ef:	xor    %eax,%eax
  4009f1:	callq  400b00 <ck_error>
  4009f6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a00 <_start>:
  400a00:	xor    %ebp,%ebp
  400a02:	mov    %rdx,%r9
  400a05:	pop    %rsi
  400a06:	mov    %rsp,%rdx
  400a09:	and    $0xfffffffffffffff0,%rsp
  400a0d:	push   %rax
  400a0e:	push   %rsp
  400a0f:	mov    $0x400f70,%r8
  400a16:	mov    $0x400f00,%rcx
  400a1d:	mov    $0x4007e0,%rdi
  400a24:	callq  *0x2015be(%rip)        # 601fe8 <_DYNAMIC+0x1f0>
  400a2a:	hlt    
  400a2b:	nopl   0x0(%rax,%rax,1)

0000000000400a30 <deregister_tm_clones>:
  400a30:	mov    $0x602077,%eax
  400a35:	push   %rbp
  400a36:	sub    $0x602070,%rax
  400a3c:	cmp    $0xe,%rax
  400a40:	mov    %rsp,%rbp
  400a43:	jbe    400a60 <deregister_tm_clones+0x30>
  400a45:	mov    $0x0,%eax
  400a4a:	test   %rax,%rax
  400a4d:	je     400a60 <deregister_tm_clones+0x30>
  400a4f:	pop    %rbp
  400a50:	mov    $0x602070,%edi
  400a55:	jmpq   *%rax
  400a57:	nopw   0x0(%rax,%rax,1)
  400a60:	pop    %rbp
  400a61:	retq   
  400a62:	nopl   0x0(%rax)
  400a66:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a70 <register_tm_clones>:
  400a70:	mov    $0x602070,%esi
  400a75:	push   %rbp
  400a76:	sub    $0x602070,%rsi
  400a7d:	sar    $0x3,%rsi
  400a81:	mov    %rsp,%rbp
  400a84:	mov    %rsi,%rax
  400a87:	shr    $0x3f,%rax
  400a8b:	add    %rax,%rsi
  400a8e:	sar    %rsi
  400a91:	je     400aa8 <register_tm_clones+0x38>
  400a93:	mov    $0x0,%eax
  400a98:	test   %rax,%rax
  400a9b:	je     400aa8 <register_tm_clones+0x38>
  400a9d:	pop    %rbp
  400a9e:	mov    $0x602070,%edi
  400aa3:	jmpq   *%rax
  400aa5:	nopl   (%rax)
  400aa8:	pop    %rbp
  400aa9:	retq   
  400aaa:	nopw   0x0(%rax,%rax,1)

0000000000400ab0 <__do_global_dtors_aux>:
  400ab0:	cmpb   $0x0,0x2015c9(%rip)        # 602080 <completed.6917>
  400ab7:	jne    400aca <__do_global_dtors_aux+0x1a>
  400ab9:	push   %rbp
  400aba:	mov    %rsp,%rbp
  400abd:	callq  400a30 <deregister_tm_clones>
  400ac2:	pop    %rbp
  400ac3:	movb   $0x1,0x2015b6(%rip)        # 602080 <completed.6917>
  400aca:	repz retq 
  400acc:	nopl   0x0(%rax)

0000000000400ad0 <frame_dummy>:
  400ad0:	mov    $0x601df0,%edi
  400ad5:	cmpq   $0x0,(%rdi)
  400ad9:	jne    400ae0 <frame_dummy+0x10>
  400adb:	jmp    400a70 <register_tm_clones>
  400add:	nopl   (%rax)
  400ae0:	mov    $0x0,%eax
  400ae5:	test   %rax,%rax
  400ae8:	je     400adb <frame_dummy+0xb>
  400aea:	push   %rbp
  400aeb:	mov    %rsp,%rbp
  400aee:	callq  *%rax
  400af0:	pop    %rbp
  400af1:	jmpq   400a70 <register_tm_clones>
  400af6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b00 <ck_error>:
  400b00:	sub    $0xd8,%rsp
  400b07:	test   %al,%al
  400b09:	mov    %rsi,0x28(%rsp)
  400b0e:	mov    %rdx,0x30(%rsp)
  400b13:	mov    %rcx,0x38(%rsp)
  400b18:	mov    %r8,0x40(%rsp)
  400b1d:	mov    %r9,0x48(%rsp)
  400b22:	je     400b5b <ck_error+0x5b>
  400b24:	movaps %xmm0,0x50(%rsp)
  400b29:	movaps %xmm1,0x60(%rsp)
  400b2e:	movaps %xmm2,0x70(%rsp)
  400b33:	movaps %xmm3,0x80(%rsp)
  400b3b:	movaps %xmm4,0x90(%rsp)
  400b43:	movaps %xmm5,0xa0(%rsp)
  400b4b:	movaps %xmm6,0xb0(%rsp)
  400b53:	movaps %xmm7,0xc0(%rsp)
  400b5b:	lea    0xe0(%rsp),%rax
  400b63:	mov    %rdi,%rsi
  400b66:	lea    0x8(%rsp),%rdx
  400b6b:	mov    %rax,0x10(%rsp)
  400b70:	lea    0x20(%rsp),%rax
  400b75:	movl   $0x8,0x8(%rsp)
  400b7d:	movl   $0x30,0xc(%rsp)
  400b85:	mov    %rax,0x18(%rsp)
  400b8a:	mov    0x201467(%rip),%rax        # 601ff8 <_DYNAMIC+0x200>
  400b91:	mov    (%rax),%rdi
  400b94:	callq  4007b0 <vfprintf@plt>
  400b99:	mov    $0x1,%edi
  400b9e:	callq  4007c0 <exit@plt>
  400ba3:	nopl   (%rax)
  400ba6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400bb0 <thread>:
  400bb0:	push   %r12
  400bb2:	push   %rbp
  400bb3:	mov    $0x40,%edi
  400bb8:	push   %rbx
  400bb9:	add    $0xffffffffffffff80,%rsp
  400bbd:	callq  400780 <malloc@plt>
  400bc2:	mov    0x201550(%rip),%esi        # 602118 <a>
  400bc8:	mov    %rax,%rbx
  400bcb:	lock xadd %esi,0x201549(%rip)        # 60211c <a+0x4>
  400bd3:	xor    %eax,%eax
  400bd5:	mov    $0x10,%ecx
  400bda:	mov    %rsp,%rdi
  400bdd:	rep stos %rax,%es:(%rdi)
  400be0:	and    $0x3,%esi
  400be3:	mov    $0x1,%eax
  400be8:	mov    $0xba,%edi
  400bed:	mov    %esi,%ecx
  400bef:	mov    %esi,%ebp
  400bf1:	shl    %cl,%rax
  400bf4:	mov    %rax,(%rsp)
  400bf8:	xor    %eax,%eax
  400bfa:	callq  400760 <syscall@plt>
  400bff:	mov    %rsp,%rdx
  400c02:	mov    $0x80,%esi
  400c07:	mov    %eax,%edi
  400c09:	callq  400750 <sched_setaffinity@plt>
  400c0e:	test   %eax,%eax
  400c10:	jne    400eb6 <thread+0x306>
  400c16:	mov    %ebp,%ecx
  400c18:	lea    0x2014a1(%rip),%r10        # 6020c0 <local_lock>
  400c1f:	lea    0x2014da(%rip),%r11        # 602100 <glob_lock>
  400c26:	shr    %ecx
  400c28:	mov    %rbx,%rax
  400c2b:	mov    $0xf4240,%r8d
  400c31:	mov    %ecx,%r9d
  400c34:	lea    (%r10,%r9,8),%rdi
  400c38:	nopl   0x0(%rax,%rax,1)
  400c40:	mov    (%r10,%r9,8),%rdx
  400c44:	movl   $0x1,(%rax)
  400c4a:	movl   $0x0,0x4(%rax)
  400c51:	mov    0x8(%rdx),%edx
  400c54:	mov    %edx,0x8(%rax)
  400c57:	mov    %rax,%rdx
  400c5a:	xchg   %rdx,(%rdi)
  400c5d:	mov    %rdx,0x10(%rax)
  400c61:	cmpq   $0x0,0x10(%rdx)
  400c66:	je     400c74 <thread+0xc4>
  400c68:	mov    0x8(%rax),%ebx
  400c6b:	cmp    %ebx,0x8(%rdx)
  400c6e:	je     400e82 <thread+0x2d2>
  400c74:	mov    (%rdi),%rdx
  400c77:	mov    %rdx,%rcx
  400c7a:	xchg   %rcx,0x20147f(%rip)        # 602100 <glob_lock>
  400c81:	movl   $0x1,0x4(%rdx)
  400c88:	mov    (%rcx),%edx
  400c8a:	cmp    $0x1,%edx
  400c8d:	jne    400c99 <thread+0xe9>
  400c8f:	nop
  400c90:	pause  
  400c92:	mov    (%rcx),%edx
  400c94:	cmp    $0x1,%edx
  400c97:	je     400c90 <thread+0xe0>
  400c99:	mov    (%r11),%rdx
  400c9c:	mov    (%rdx),%edx
  400c9e:	test   %edx,%edx
  400ca0:	je     400ecc <thread+0x31c>
  400ca6:	mov    0x201464(%rip),%ebx        # 602110 <locked>
  400cac:	lea    0x1(%rbx),%edx
  400caf:	mov    %edx,0x20145b(%rip)        # 602110 <locked>
  400cb5:	mov    0x201455(%rip),%ebx        # 602110 <locked>
  400cbb:	lea    0x1(%rbx),%edx
  400cbe:	mov    %edx,0x20144c(%rip)        # 602110 <locked>
  400cc4:	mov    0x201446(%rip),%ebx        # 602110 <locked>
  400cca:	lea    0x1(%rbx),%edx
  400ccd:	mov    %edx,0x20143d(%rip)        # 602110 <locked>
  400cd3:	mov    0x201437(%rip),%esi        # 602110 <locked>
  400cd9:	lea    0x1(%rsi),%edx
  400cdc:	mov    %edx,0x20142e(%rip)        # 602110 <locked>
  400ce2:	mov    0x201428(%rip),%ebx        # 602110 <locked>
  400ce8:	lea    0x1(%rbx),%edx
  400ceb:	mov    %edx,0x20141f(%rip)        # 602110 <locked>
  400cf1:	mov    0x201419(%rip),%esi        # 602110 <locked>
  400cf7:	lea    0x1(%rsi),%edx
  400cfa:	mov    %edx,0x201410(%rip)        # 602110 <locked>
  400d00:	mov    0x20140a(%rip),%ebx        # 602110 <locked>
  400d06:	lea    0x1(%rbx),%edx
  400d09:	mov    %edx,0x201401(%rip)        # 602110 <locked>
  400d0f:	mov    0x2013fb(%rip),%esi        # 602110 <locked>
  400d15:	lea    0x1(%rsi),%edx
  400d18:	mov    %edx,0x2013f2(%rip)        # 602110 <locked>
  400d1e:	mov    0x2013ec(%rip),%ebx        # 602110 <locked>
  400d24:	lea    0x1(%rbx),%edx
  400d27:	mov    %edx,0x2013e3(%rip)        # 602110 <locked>
  400d2d:	mov    0x2013dd(%rip),%esi        # 602110 <locked>
  400d33:	lea    0x1(%rsi),%edx
  400d36:	mov    %edx,0x2013d4(%rip)        # 602110 <locked>
  400d3c:	mov    0x2013ce(%rip),%esi        # 602110 <locked>
  400d42:	cmp    $0xa,%esi
  400d45:	jne    400eda <thread+0x32a>
  400d4b:	mov    0x2013bf(%rip),%ebx        # 602110 <locked>
  400d51:	lea    -0x1(%rbx),%edx
  400d54:	mov    %edx,0x2013b6(%rip)        # 602110 <locked>
  400d5a:	mov    0x2013b0(%rip),%esi        # 602110 <locked>
  400d60:	lea    -0x1(%rsi),%edx
  400d63:	mov    %edx,0x2013a7(%rip)        # 602110 <locked>
  400d69:	mov    0x2013a1(%rip),%ebx        # 602110 <locked>
  400d6f:	lea    -0x1(%rbx),%edx
  400d72:	mov    %edx,0x201398(%rip)        # 602110 <locked>
  400d78:	mov    0x201392(%rip),%esi        # 602110 <locked>
  400d7e:	lea    -0x1(%rsi),%edx
  400d81:	mov    %edx,0x201389(%rip)        # 602110 <locked>
  400d87:	mov    0x201383(%rip),%ebx        # 602110 <locked>
  400d8d:	lea    -0x1(%rbx),%edx
  400d90:	mov    %edx,0x20137a(%rip)        # 602110 <locked>
  400d96:	mov    0x201374(%rip),%esi        # 602110 <locked>
  400d9c:	lea    -0x1(%rsi),%edx
  400d9f:	mov    %edx,0x20136b(%rip)        # 602110 <locked>
  400da5:	mov    0x201365(%rip),%ebx        # 602110 <locked>
  400dab:	lea    -0x1(%rbx),%edx
  400dae:	mov    %edx,0x20135c(%rip)        # 602110 <locked>
  400db4:	mov    0x201356(%rip),%esi        # 602110 <locked>
  400dba:	lea    -0x1(%rsi),%edx
  400dbd:	mov    %edx,0x20134d(%rip)        # 602110 <locked>
  400dc3:	mov    0x201347(%rip),%ebx        # 602110 <locked>
  400dc9:	lea    -0x1(%rbx),%edx
  400dcc:	mov    %edx,0x20133e(%rip)        # 602110 <locked>
  400dd2:	mov    0x201338(%rip),%esi        # 602110 <locked>
  400dd8:	lea    -0x1(%rsi),%edx
  400ddb:	mov    %edx,0x20132f(%rip)        # 602110 <locked>
  400de1:	mov    0x10(%rax),%rcx
  400de5:	movl   $0x0,(%rax)
  400deb:	mov    (%r10,%r9,8),%rax
  400def:	movl   $0x1,(%rcx)
  400df5:	movl   $0x0,0x4(%rcx)
  400dfc:	mov    0x8(%rax),%eax
  400dff:	mov    %eax,0x8(%rcx)
  400e02:	mov    %rcx,%rax
  400e05:	xchg   %rax,(%rdi)
  400e08:	mov    %rax,0x10(%rcx)
  400e0c:	cmpq   $0x0,0x10(%rax)
  400e11:	je     400e1f <thread+0x26f>
  400e13:	mov    0x8(%rcx),%esi
  400e16:	cmp    %esi,0x8(%rax)
  400e19:	je     400ea2 <thread+0x2f2>
  400e1f:	mov    (%rdi),%rax
  400e22:	mov    %rax,%rdx
  400e25:	xchg   %rdx,0x2012d4(%rip)        # 602100 <glob_lock>
  400e2c:	movl   $0x1,0x4(%rax)
  400e33:	mov    (%rdx),%eax
  400e35:	cmp    $0x1,%eax
  400e38:	jne    400e49 <thread+0x299>
  400e3a:	nopw   0x0(%rax,%rax,1)
  400e40:	pause  
  400e42:	mov    (%rdx),%eax
  400e44:	cmp    $0x1,%eax
  400e47:	je     400e40 <thread+0x290>
  400e49:	mov    0x2012c1(%rip),%esi        # 602110 <locked>
  400e4f:	test   %esi,%esi
  400e51:	jne    400ee8 <thread+0x338>
  400e57:	mov    0x10(%rcx),%rax
  400e5b:	movl   $0x0,(%rcx)
  400e61:	sub    $0x1,%r8d
  400e65:	jne    400c40 <thread+0x90>
  400e6b:	sub    $0xffffffffffffff80,%rsp
  400e6f:	xor    %eax,%eax
  400e71:	pop    %rbx
  400e72:	pop    %rbp
  400e73:	pop    %r12
  400e75:	retq   
  400e76:	nopw   %cs:0x0(%rax,%rax,1)
  400e80:	pause  
  400e82:	mov    (%rdx),%ecx
  400e84:	cmp    $0x1,%ecx
  400e87:	je     400e80 <thread+0x2d0>
  400e89:	mov    0x4(%rdx),%edx
  400e8c:	test   %edx,%edx
  400e8e:	jne    400c74 <thread+0xc4>
  400e94:	jmpq   400c99 <thread+0xe9>
  400e99:	nopl   0x0(%rax)
  400ea0:	pause  
  400ea2:	mov    (%rax),%edx
  400ea4:	cmp    $0x1,%edx
  400ea7:	je     400ea0 <thread+0x2f0>
  400ea9:	mov    0x4(%rax),%eax
  400eac:	test   %eax,%eax
  400eae:	jne    400e1f <thread+0x26f>
  400eb4:	jmp    400e49 <thread+0x299>
  400eb6:	lea    0xd3(%rip),%rdi        # 400f90 <__dso_handle+0x8>
  400ebd:	callq  400790 <perror@plt>
  400ec2:	mov    $0x1,%edi
  400ec7:	callq  4007c0 <exit@plt>
  400ecc:	lea    0x255(%rip),%rdi        # 401128 <__dso_handle+0x1a0>
  400ed3:	xor    %eax,%eax
  400ed5:	callq  400b00 <ck_error>
  400eda:	lea    0xcf(%rip),%rdi        # 400fb0 <__dso_handle+0x28>
  400ee1:	xor    %eax,%eax
  400ee3:	callq  400b00 <ck_error>
  400ee8:	lea    0xe9(%rip),%rdi        # 400fd8 <__dso_handle+0x50>
  400eef:	xor    %eax,%eax
  400ef1:	callq  400b00 <ck_error>
  400ef6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400f00 <__libc_csu_init>:
  400f00:	push   %r15
  400f02:	push   %r14
  400f04:	mov    %edi,%r15d
  400f07:	push   %r13
  400f09:	push   %r12
  400f0b:	lea    0x200ece(%rip),%r12        # 601de0 <__frame_dummy_init_array_entry>
  400f12:	push   %rbp
  400f13:	lea    0x200ece(%rip),%rbp        # 601de8 <__init_array_end>
  400f1a:	push   %rbx
  400f1b:	mov    %rsi,%r14
  400f1e:	mov    %rdx,%r13
  400f21:	sub    %r12,%rbp
  400f24:	sub    $0x8,%rsp
  400f28:	sar    $0x3,%rbp
  400f2c:	callq  400710 <_init>
  400f31:	test   %rbp,%rbp
  400f34:	je     400f56 <__libc_csu_init+0x56>
  400f36:	xor    %ebx,%ebx
  400f38:	nopl   0x0(%rax,%rax,1)
  400f40:	mov    %r13,%rdx
  400f43:	mov    %r14,%rsi
  400f46:	mov    %r15d,%edi
  400f49:	callq  *(%r12,%rbx,8)
  400f4d:	add    $0x1,%rbx
  400f51:	cmp    %rbx,%rbp
  400f54:	jne    400f40 <__libc_csu_init+0x40>
  400f56:	add    $0x8,%rsp
  400f5a:	pop    %rbx
  400f5b:	pop    %rbp
  400f5c:	pop    %r12
  400f5e:	pop    %r13
  400f60:	pop    %r14
  400f62:	pop    %r15
  400f64:	retq   
  400f65:	nop
  400f66:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400f70 <__libc_csu_fini>:
  400f70:	repz retq 

Disassembly of section .fini:

0000000000400f74 <_fini>:
  400f74:	sub    $0x8,%rsp
  400f78:	add    $0x8,%rsp
  400f7c:	retq   
