// TC_OUT thread,0x400c70,0x400c7e,0x0(0x0(%rcx),0x0(%rsp),8)
// TC_OUT thread,0x400e60,0x400e6e,0x0(0x0(%rcx),0x0(%rsp),8)

ck_anderson:     file format elf64-x86-64


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
  4007eb:	jne    4009e9 <main+0x209>
  4007f1:	mov    0x8(%rsi),%rdi
  4007f5:	mov    %rsi,%r13
  4007f8:	mov    $0xa,%edx
  4007fd:	xor    %esi,%esi
  4007ff:	callq  400770 <strtol@plt>
  400804:	movslq %eax,%rbp
  400807:	test   %rbp,%rbp
  40080a:	mov    %rbp,0x2018f7(%rip)        # 602108 <nthr>
  400811:	je     4009db <main+0x1fb>
  400817:	mov    %rbp,%rdi
  40081a:	mov    %ebp,%ebx
  40081c:	shl    $0x6,%rdi
  400820:	callq  400780 <malloc@plt>
  400825:	cmp    $0x1,%ebp
  400828:	movl   $0x0,(%rax)
  40082e:	movl   $0x0,0x4(%rax)
  400835:	lea    0x8(%rax),%rcx
  400839:	mov    $0x1,%edx
  40083e:	jbe    400854 <main+0x74>
  400840:	mov    %edx,0x4(%rcx)
  400843:	add    $0x1,%edx
  400846:	movl   $0x1,(%rcx)
  40084c:	add    $0x8,%rcx
  400850:	cmp    %edx,%ebx
  400852:	ja     400840 <main+0x60>
  400854:	mov    %rax,0x201865(%rip)        # 6020c0 <lock>
  40085b:	lea    -0x1(%rbp),%eax
  40085e:	mov    %ebp,0x201864(%rip)        # 6020c8 <lock+0x8>
  400864:	movl   $0x0,0x201892(%rip)        # 602100 <lock+0x40>
  40086e:	test   %ebp,%eax
  400870:	mov    %eax,0x20185a(%rip)        # 6020d0 <lock+0x10>
  400876:	je     4009ad <main+0x1cd>
  40087c:	or     $0xffffffff,%eax
  40087f:	xor    %edx,%edx
  400881:	div    %ebx
  400883:	add    $0x1,%edx
  400886:	mov    %edx,0x201840(%rip)        # 6020cc <lock+0xc>
  40088c:	mov    0x201875(%rip),%rax        # 602108 <nthr>
  400893:	lea    0x0(,%rax,8),%rdi
  40089b:	callq  400780 <malloc@plt>
  4008a0:	test   %rax,%rax
  4008a3:	mov    %rax,%r12
  4008a6:	je     4009cd <main+0x1ed>
  4008ac:	mov    0x10(%r13),%rdi
  4008b0:	xor    %esi,%esi
  4008b2:	mov    $0xa,%edx
  4008b7:	xor    %ebx,%ebx
  4008b9:	mov    %r12,%rbp
  4008bc:	lea    0x2ed(%rip),%r14        # 400bb0 <thread>
  4008c3:	callq  400770 <strtol@plt>
  4008c8:	mov    0x201729(%rip),%r13        # 601ff8 <_DYNAMIC+0x200>
  4008cf:	lea    0x852(%rip),%rdi        # 401128 <__dso_handle+0x120>
  4008d6:	mov    $0x26,%edx
  4008db:	mov    $0x1,%esi
  4008e0:	mov    %eax,0x201832(%rip)        # 602118 <a>
  4008e6:	movl   $0x0,0x20182c(%rip)        # 60211c <a+0x4>
  4008f0:	mov    0x0(%r13),%rcx
  4008f4:	callq  4007d0 <fwrite@plt>
  4008f9:	cmpq   $0x0,0x201807(%rip)        # 602108 <nthr>
  400901:	je     400930 <main+0x150>
  400903:	nopl   0x0(%rax,%rax,1)
  400908:	xor    %ecx,%ecx
  40090a:	xor    %esi,%esi
  40090c:	mov    %r14,%rdx
  40090f:	mov    %rbp,%rdi
  400912:	callq  400740 <pthread_create@plt>
  400917:	test   %eax,%eax
  400919:	jne    4009bc <main+0x1dc>
  40091f:	add    $0x1,%rbx
  400923:	add    $0x8,%rbp
  400927:	cmp    %rbx,0x2017da(%rip)        # 602108 <nthr>
  40092e:	ja     400908 <main+0x128>
  400930:	mov    0x0(%r13),%rcx
  400934:	lea    0x891(%rip),%rdi        # 4011cc <__dso_handle+0x1c4>
  40093b:	mov    $0x5,%edx
  400940:	mov    $0x1,%esi
  400945:	xor    %ebx,%ebx
  400947:	callq  4007d0 <fwrite@plt>
  40094c:	mov    0x0(%r13),%rcx
  400950:	lea    0x7f9(%rip),%rdi        # 401150 <__dso_handle+0x148>
  400957:	mov    $0x37,%edx
  40095c:	mov    $0x1,%esi
  400961:	callq  4007d0 <fwrite@plt>
  400966:	cmpq   $0x0,0x20179a(%rip)        # 602108 <nthr>
  40096e:	je     400988 <main+0x1a8>
  400970:	mov    (%r12,%rbx,8),%rdi
  400974:	xor    %esi,%esi
  400976:	add    $0x1,%rbx
  40097a:	callq  4007a0 <pthread_join@plt>
  40097f:	cmp    %rbx,0x201782(%rip)        # 602108 <nthr>
  400986:	ja     400970 <main+0x190>
  400988:	mov    0x0(%r13),%rcx
  40098c:	lea    0x83f(%rip),%rdi        # 4011d2 <__dso_handle+0x1ca>
  400993:	mov    $0xe,%edx
  400998:	mov    $0x1,%esi
  40099d:	callq  4007d0 <fwrite@plt>
  4009a2:	pop    %rbx
  4009a3:	xor    %eax,%eax
  4009a5:	pop    %rbp
  4009a6:	pop    %r12
  4009a8:	pop    %r13
  4009aa:	pop    %r14
  4009ac:	retq   
  4009ad:	movl   $0x0,0x201715(%rip)        # 6020cc <lock+0xc>
  4009b7:	jmpq   40088c <main+0xac>
  4009bc:	lea    0x7c5(%rip),%rdi        # 401188 <__dso_handle+0x180>
  4009c3:	mov    %rbx,%rsi
  4009c6:	xor    %eax,%eax
  4009c8:	callq  400b00 <ck_error>
  4009cd:	lea    0x724(%rip),%rdi        # 4010f8 <__dso_handle+0xf0>
  4009d4:	xor    %eax,%eax
  4009d6:	callq  400b00 <ck_error>
  4009db:	lea    0x6de(%rip),%rdi        # 4010c0 <__dso_handle+0xb8>
  4009e2:	xor    %eax,%eax
  4009e4:	callq  400b00 <ck_error>
  4009e9:	lea    0x690(%rip),%rdi        # 401080 <__dso_handle+0x78>
  4009f0:	xor    %eax,%eax
  4009f2:	callq  400b00 <ck_error>
  4009f7:	nopw   0x0(%rax,%rax,1)

0000000000400a00 <_start>:
  400a00:	xor    %ebp,%ebp
  400a02:	mov    %rdx,%r9
  400a05:	pop    %rsi
  400a06:	mov    %rsp,%rdx
  400a09:	and    $0xfffffffffffffff0,%rsp
  400a0d:	push   %rax
  400a0e:	push   %rsp
  400a0f:	mov    $0x400ff0,%r8
  400a16:	mov    $0x400f80,%rcx
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
  400bb0:	push   %rbx
  400bb1:	add    $0xffffffffffffff80,%rsp
  400bb5:	mov    0x20155d(%rip),%esi        # 602118 <a>
  400bbb:	lock xadd %esi,0x201559(%rip)        # 60211c <a+0x4>
  400bc3:	xor    %eax,%eax
  400bc5:	mov    $0x10,%ecx
  400bca:	mov    %rsp,%rdi
  400bcd:	rep stos %rax,%es:(%rdi)
  400bd0:	and    $0x3,%esi
  400bd3:	mov    $0x1,%eax
  400bd8:	mov    $0xba,%edi
  400bdd:	mov    %esi,%ecx
  400bdf:	shl    %cl,%rax
  400be2:	mov    %rax,(%rsp)
  400be6:	xor    %eax,%eax
  400be8:	callq  400760 <syscall@plt>
  400bed:	mov    %rsp,%rdx
  400bf0:	mov    $0x80,%esi
  400bf5:	mov    %eax,%edi
  400bf7:	callq  400750 <sched_setaffinity@plt>
  400bfc:	test   %eax,%eax
  400bfe:	jne    400f38 <thread+0x388>
  400c04:	lea    0x2014b5(%rip),%rcx        # 6020c0 <lock>
  400c0b:	mov    $0xf4240,%edi
  400c10:	mov    $0x1,%r8d
  400c16:	nopw   %cs:0x0(%rax,%rax,1)
  400c20:	mov    0x2014a5(%rip),%r9d        # 6020cc <lock+0xc>
  400c27:	test   %r9d,%r9d
  400c2a:	je     400f08 <thread+0x358>
  400c30:	mov    0x201492(%rip),%esi        # 6020c8 <lock+0x8>
  400c36:	mov    0x2014c4(%rip),%eax        # 602100 <lock+0x40>
  400c3c:	mov    %eax,(%rsp)
  400c3f:	nop
  400c40:	lea    0x1(%rax),%edx
  400c43:	cmp    $0xffffffff,%eax
  400c46:	cmove  0x20147f(%rip),%edx        # 6020cc <lock+0xc>
  400c4d:	lock cmpxchg %edx,0x2014ab(%rip)        # 602100 <lock+0x40>
  400c55:	mov    %eax,(%rsp)
  400c58:	sete   %al
  400c5b:	test   %al,%al
  400c5d:	mov    (%rsp),%eax
  400c60:	je     400c40 <thread+0x90>
  400c62:	xor    %edx,%edx
  400c64:	div    %esi
  400c66:	mov    %edx,(%rsp)
  400c69:	jmp    400c72 <thread+0xc2>
  400c6b:	nopl   0x0(%rax,%rax,1)
  400c70:	pause  
  400c72:	mov    (%rsp),%edx
  400c75:	mov    (%rcx),%rax
  400c78:	mov    (%rax,%rdx,8),%eax
  400c7b:	cmp    $0x1,%eax
  400c7e:	je     400c70 <thread+0xc0>
  400c80:	mov    (%rsp),%edx
  400c83:	mov    (%rcx),%rax
  400c86:	movl   $0x1,(%rax,%rdx,8)
  400c8d:	mov    (%rsp),%edx
  400c90:	mov    (%rcx),%rax
  400c93:	lea    (%rax,%rdx,8),%rdx
  400c97:	mov    0x201463(%rip),%eax        # 602100 <lock+0x40>
  400c9d:	and    0x20142d(%rip),%eax        # 6020d0 <lock+0x10>
  400ca3:	mov    (%rcx),%rsi
  400ca6:	mov    (%rsi,%rax,8),%eax
  400ca9:	test   %eax,%eax
  400cab:	je     400f4e <thread+0x39e>
  400cb1:	mov    0x201459(%rip),%eax        # 602110 <locked>
  400cb7:	add    $0x1,%eax
  400cba:	mov    %eax,0x201450(%rip)        # 602110 <locked>
  400cc0:	mov    0x20144a(%rip),%eax        # 602110 <locked>
  400cc6:	add    $0x1,%eax
  400cc9:	mov    %eax,0x201441(%rip)        # 602110 <locked>
  400ccf:	mov    0x20143b(%rip),%eax        # 602110 <locked>
  400cd5:	add    $0x1,%eax
  400cd8:	mov    %eax,0x201432(%rip)        # 602110 <locked>
  400cde:	mov    0x20142c(%rip),%eax        # 602110 <locked>
  400ce4:	add    $0x1,%eax
  400ce7:	mov    %eax,0x201423(%rip)        # 602110 <locked>
  400ced:	mov    0x20141d(%rip),%eax        # 602110 <locked>
  400cf3:	add    $0x1,%eax
  400cf6:	mov    %eax,0x201414(%rip)        # 602110 <locked>
  400cfc:	mov    0x20140e(%rip),%eax        # 602110 <locked>
  400d02:	add    $0x1,%eax
  400d05:	mov    %eax,0x201405(%rip)        # 602110 <locked>
  400d0b:	mov    0x2013ff(%rip),%eax        # 602110 <locked>
  400d11:	add    $0x1,%eax
  400d14:	mov    %eax,0x2013f6(%rip)        # 602110 <locked>
  400d1a:	mov    0x2013f0(%rip),%eax        # 602110 <locked>
  400d20:	add    $0x1,%eax
  400d23:	mov    %eax,0x2013e7(%rip)        # 602110 <locked>
  400d29:	mov    0x2013e1(%rip),%eax        # 602110 <locked>
  400d2f:	add    $0x1,%eax
  400d32:	mov    %eax,0x2013d8(%rip)        # 602110 <locked>
  400d38:	mov    0x2013d2(%rip),%eax        # 602110 <locked>
  400d3e:	add    $0x1,%eax
  400d41:	mov    %eax,0x2013c9(%rip)        # 602110 <locked>
  400d47:	mov    0x2013c3(%rip),%esi        # 602110 <locked>
  400d4d:	cmp    $0xa,%esi
  400d50:	jne    400f5c <thread+0x3ac>
  400d56:	mov    0x2013b4(%rip),%eax        # 602110 <locked>
  400d5c:	sub    $0x1,%eax
  400d5f:	mov    %eax,0x2013ab(%rip)        # 602110 <locked>
  400d65:	mov    0x2013a5(%rip),%eax        # 602110 <locked>
  400d6b:	sub    $0x1,%eax
  400d6e:	mov    %eax,0x20139c(%rip)        # 602110 <locked>
  400d74:	mov    0x201396(%rip),%eax        # 602110 <locked>
  400d7a:	sub    $0x1,%eax
  400d7d:	mov    %eax,0x20138d(%rip)        # 602110 <locked>
  400d83:	mov    0x201387(%rip),%eax        # 602110 <locked>
  400d89:	sub    $0x1,%eax
  400d8c:	mov    %eax,0x20137e(%rip)        # 602110 <locked>
  400d92:	mov    0x201378(%rip),%eax        # 602110 <locked>
  400d98:	sub    $0x1,%eax
  400d9b:	mov    %eax,0x20136f(%rip)        # 602110 <locked>
  400da1:	mov    0x201369(%rip),%eax        # 602110 <locked>
  400da7:	sub    $0x1,%eax
  400daa:	mov    %eax,0x201360(%rip)        # 602110 <locked>
  400db0:	mov    0x20135a(%rip),%eax        # 602110 <locked>
  400db6:	sub    $0x1,%eax
  400db9:	mov    %eax,0x201351(%rip)        # 602110 <locked>
  400dbf:	mov    0x20134b(%rip),%eax        # 602110 <locked>
  400dc5:	sub    $0x1,%eax
  400dc8:	mov    %eax,0x201342(%rip)        # 602110 <locked>
  400dce:	mov    0x20133c(%rip),%eax        # 602110 <locked>
  400dd4:	sub    $0x1,%eax
  400dd7:	mov    %eax,0x201333(%rip)        # 602110 <locked>
  400ddd:	mov    0x20132d(%rip),%eax        # 602110 <locked>
  400de3:	sub    $0x1,%eax
  400de6:	mov    %eax,0x201324(%rip)        # 602110 <locked>
  400dec:	mov    0x2012da(%rip),%esi        # 6020cc <lock+0xc>
  400df2:	test   %esi,%esi
  400df4:	jne    400ef0 <thread+0x340>
  400dfa:	mov    0x4(%rdx),%edx
  400dfd:	add    $0x1,%edx
  400e00:	and    0x2012ca(%rip),%edx        # 6020d0 <lock+0x10>
  400e06:	mov    %edx,%edx
  400e08:	mov    (%rcx),%rax
  400e0b:	movl   $0x0,(%rax,%rdx,8)
  400e12:	mov    0x2012b4(%rip),%edx        # 6020cc <lock+0xc>
  400e18:	test   %edx,%edx
  400e1a:	je     400ed0 <thread+0x320>
  400e20:	mov    0x2012a2(%rip),%esi        # 6020c8 <lock+0x8>
  400e26:	mov    0x2012d4(%rip),%eax        # 602100 <lock+0x40>
  400e2c:	mov    %eax,(%rsp)
  400e2f:	nop
  400e30:	lea    0x1(%rax),%edx
  400e33:	cmp    $0xffffffff,%eax
  400e36:	cmove  0x20128f(%rip),%edx        # 6020cc <lock+0xc>
  400e3d:	lock cmpxchg %edx,0x2012bb(%rip)        # 602100 <lock+0x40>
  400e45:	mov    %eax,(%rsp)
  400e48:	sete   %al
  400e4b:	test   %al,%al
  400e4d:	mov    (%rsp),%eax
  400e50:	je     400e30 <thread+0x280>
  400e52:	xor    %edx,%edx
  400e54:	div    %esi
  400e56:	mov    %edx,(%rsp)
  400e59:	jmp    400e62 <thread+0x2b2>
  400e5b:	nopl   0x0(%rax,%rax,1)
  400e60:	pause  
  400e62:	mov    (%rsp),%edx
  400e65:	mov    (%rcx),%rax
  400e68:	mov    (%rax,%rdx,8),%eax
  400e6b:	cmp    $0x1,%eax
  400e6e:	je     400e60 <thread+0x2b0>
  400e70:	mov    (%rsp),%edx
  400e73:	mov    (%rcx),%rax
  400e76:	movl   $0x1,(%rax,%rdx,8)
  400e7d:	mov    (%rsp),%edx
  400e80:	mov    (%rcx),%rax
  400e83:	lea    (%rax,%rdx,8),%rax
  400e87:	mov    0x201283(%rip),%esi        # 602110 <locked>
  400e8d:	test   %esi,%esi
  400e8f:	jne    400f6a <thread+0x3ba>
  400e95:	mov    0x4(%rax),%edx
  400e98:	mov    0x20122e(%rip),%eax        # 6020cc <lock+0xc>
  400e9e:	test   %eax,%eax
  400ea0:	jne    400f28 <thread+0x378>
  400ea6:	add    $0x1,%edx
  400ea9:	and    0x201221(%rip),%edx        # 6020d0 <lock+0x10>
  400eaf:	mov    %edx,%edx
  400eb1:	mov    (%rcx),%rax
  400eb4:	movl   $0x0,(%rax,%rdx,8)
  400ebb:	sub    $0x1,%edi
  400ebe:	jne    400c20 <thread+0x70>
  400ec4:	sub    $0xffffffffffffff80,%rsp
  400ec8:	xor    %eax,%eax
  400eca:	pop    %rbx
  400ecb:	retq   
  400ecc:	nopl   0x0(%rax)
  400ed0:	mov    %r8d,%eax
  400ed3:	lock xadd %eax,0x201225(%rip)        # 602100 <lock+0x40>
  400edb:	and    0x2011ef(%rip),%eax        # 6020d0 <lock+0x10>
  400ee1:	mov    %eax,(%rsp)
  400ee4:	jmpq   400e59 <thread+0x2a9>
  400ee9:	nopl   0x0(%rax)
  400ef0:	mov    0x4(%rdx),%eax
  400ef3:	xor    %edx,%edx
  400ef5:	add    $0x1,%eax
  400ef8:	divl   0x2011ca(%rip)        # 6020c8 <lock+0x8>
  400efe:	jmpq   400e06 <thread+0x256>
  400f03:	nopl   0x0(%rax,%rax,1)
  400f08:	mov    %r8d,%eax
  400f0b:	lock xadd %eax,0x2011ed(%rip)        # 602100 <lock+0x40>
  400f13:	and    0x2011b7(%rip),%eax        # 6020d0 <lock+0x10>
  400f19:	mov    %eax,(%rsp)
  400f1c:	jmpq   400c69 <thread+0xb9>
  400f21:	nopl   0x0(%rax)
  400f28:	lea    0x1(%rdx),%eax
  400f2b:	xor    %edx,%edx
  400f2d:	divl   0x201195(%rip)        # 6020c8 <lock+0x8>
  400f33:	jmpq   400eaf <thread+0x2ff>
  400f38:	lea    0xd1(%rip),%rdi        # 401010 <__dso_handle+0x8>
  400f3f:	callq  400790 <perror@plt>
  400f44:	mov    $0x1,%edi
  400f49:	callq  4007c0 <exit@plt>
  400f4e:	lea    0x25b(%rip),%rdi        # 4011b0 <__dso_handle+0x1a8>
  400f55:	xor    %eax,%eax
  400f57:	callq  400b00 <ck_error>
  400f5c:	lea    0xcd(%rip),%rdi        # 401030 <__dso_handle+0x28>
  400f63:	xor    %eax,%eax
  400f65:	callq  400b00 <ck_error>
  400f6a:	lea    0xe7(%rip),%rdi        # 401058 <__dso_handle+0x50>
  400f71:	xor    %eax,%eax
  400f73:	callq  400b00 <ck_error>
  400f78:	nopl   0x0(%rax,%rax,1)

0000000000400f80 <__libc_csu_init>:
  400f80:	push   %r15
  400f82:	push   %r14
  400f84:	mov    %edi,%r15d
  400f87:	push   %r13
  400f89:	push   %r12
  400f8b:	lea    0x200e4e(%rip),%r12        # 601de0 <__frame_dummy_init_array_entry>
  400f92:	push   %rbp
  400f93:	lea    0x200e4e(%rip),%rbp        # 601de8 <__init_array_end>
  400f9a:	push   %rbx
  400f9b:	mov    %rsi,%r14
  400f9e:	mov    %rdx,%r13
  400fa1:	sub    %r12,%rbp
  400fa4:	sub    $0x8,%rsp
  400fa8:	sar    $0x3,%rbp
  400fac:	callq  400710 <_init>
  400fb1:	test   %rbp,%rbp
  400fb4:	je     400fd6 <__libc_csu_init+0x56>
  400fb6:	xor    %ebx,%ebx
  400fb8:	nopl   0x0(%rax,%rax,1)
  400fc0:	mov    %r13,%rdx
  400fc3:	mov    %r14,%rsi
  400fc6:	mov    %r15d,%edi
  400fc9:	callq  *(%r12,%rbx,8)
  400fcd:	add    $0x1,%rbx
  400fd1:	cmp    %rbx,%rbp
  400fd4:	jne    400fc0 <__libc_csu_init+0x40>
  400fd6:	add    $0x8,%rsp
  400fda:	pop    %rbx
  400fdb:	pop    %rbp
  400fdc:	pop    %r12
  400fde:	pop    %r13
  400fe0:	pop    %r14
  400fe2:	pop    %r15
  400fe4:	retq   
  400fe5:	nop
  400fe6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400ff0 <__libc_csu_fini>:
  400ff0:	repz retq 

Disassembly of section .fini:

0000000000400ff4 <_fini>:
  400ff4:	sub    $0x8,%rsp
  400ff8:	add    $0x8,%rsp
  400ffc:	retq   
