// TC_OUT thread,0x400b95,0x400b9a,0x0(%rax)
// TC_OUT thread,0x400ce4,0x400ce9,0x0(%rax)

linux_spinlock:     file format elf64-x86-64


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
  400809:	mov    %rax,0x201868(%rip)        # 602078 <nthr>
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
  400852:	lea    0x68f(%rip),%rdi        # 400ee8 <__dso_handle+0x120>
  400859:	mov    $0x26,%edx
  40085e:	mov    $0x1,%esi
  400863:	mov    %eax,0x20181f(%rip)        # 602088 <a>
  400869:	movl   $0x0,0x201819(%rip)        # 60208c <a+0x4>
  400873:	mov    0x0(%r13),%rcx
  400877:	callq  4007d0 <fwrite@plt>
  40087c:	cmpq   $0x0,0x2017f4(%rip)        # 602078 <nthr>
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
  4008af:	cmp    %rbx,0x2017c2(%rip)        # 602078 <nthr>
  4008b6:	ja     400890 <main+0xb0>
  4008b8:	mov    0x0(%r13),%rcx
  4008bc:	lea    0x6ad(%rip),%rdi        # 400f70 <__dso_handle+0x1a8>
  4008c3:	mov    $0x5,%edx
  4008c8:	mov    $0x1,%esi
  4008cd:	xor    %ebx,%ebx
  4008cf:	callq  4007d0 <fwrite@plt>
  4008d4:	mov    0x0(%r13),%rcx
  4008d8:	lea    0x631(%rip),%rdi        # 400f10 <__dso_handle+0x148>
  4008df:	mov    $0x37,%edx
  4008e4:	mov    $0x1,%esi
  4008e9:	callq  4007d0 <fwrite@plt>
  4008ee:	cmpq   $0x0,0x201782(%rip)        # 602078 <nthr>
  4008f6:	je     400918 <main+0x138>
  4008f8:	nopl   0x0(%rax,%rax,1)
  400900:	mov    (%r12,%rbx,8),%rdi
  400904:	xor    %esi,%esi
  400906:	add    $0x1,%rbx
  40090a:	callq  4007a0 <pthread_join@plt>
  40090f:	cmp    %rbx,0x201762(%rip)        # 602078 <nthr>
  400916:	ja     400900 <main+0x120>
  400918:	mov    0x0(%r13),%rcx
  40091c:	lea    0x653(%rip),%rdi        # 400f76 <__dso_handle+0x1ae>
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
  40093d:	lea    0x604(%rip),%rdi        # 400f48 <__dso_handle+0x180>
  400944:	mov    %rbx,%rsi
  400947:	xor    %eax,%eax
  400949:	callq  400a80 <ck_error>
  40094e:	lea    0x563(%rip),%rdi        # 400eb8 <__dso_handle+0xf0>
  400955:	xor    %eax,%eax
  400957:	callq  400a80 <ck_error>
  40095c:	lea    0x51d(%rip),%rdi        # 400e80 <__dso_handle+0xb8>
  400963:	callq  400a80 <ck_error>
  400968:	lea    0x4d1(%rip),%rdi        # 400e40 <__dso_handle+0x78>
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
  40098f:	mov    $0x400db0,%r8
  400996:	mov    $0x400d40,%rcx
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
  400a30:	cmpb   $0x0,0x201639(%rip)        # 602070 <__TMC_END__>
  400a37:	jne    400a4a <__do_global_dtors_aux+0x1a>
  400a39:	push   %rbp
  400a3a:	mov    %rsp,%rbp
  400a3d:	callq  4009b0 <deregister_tm_clones>
  400a42:	pop    %rbp
  400a43:	movb   $0x1,0x201626(%rip)        # 602070 <__TMC_END__>
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
  400b35:	mov    0x20154d(%rip),%esi        # 602088 <a>
  400b3b:	lock xadd %esi,0x201549(%rip)        # 60208c <a+0x4>
  400b43:	xor    %eax,%eax
  400b45:	mov    $0x10,%ecx
  400b4a:	mov    %rsp,%rdi
  400b4d:	rep stos %rax,%es:(%rdi)
  400b50:	mov    %esi,%ecx
  400b52:	mov    $0x1,%eax
  400b57:	mov    $0xba,%edi
  400b5c:	and    $0x3,%ecx
  400b5f:	shl    %cl,%rax
  400b62:	mov    %rax,(%rsp)
  400b66:	xor    %eax,%eax
  400b68:	callq  400760 <syscall@plt>
  400b6d:	mov    %rsp,%rdx
  400b70:	mov    $0x80,%esi
  400b75:	mov    %eax,%edi
  400b77:	callq  400750 <sched_setaffinity@plt>
  400b7c:	test   %eax,%eax
  400b7e:	jne    400d2a <thread+0x1fa>
  400b84:	lea    0x2014e1(%rip),%rax        # 60206c <lock>
  400b8b:	mov    $0xf4240,%ecx
  400b90:	lock decl (%rax)
  400b93:	jns    400b9e <thread+0x6e>
  400b95:	pause  
  400b97:	cmpl   $0x0,(%rax)
  400b9a:	jle    400b95 <thread+0x65>
  400b9c:	jmp    400b90 <thread+0x60>
  400b9e:	mov    0x2014dc(%rip),%ebx        # 602080 <locked>
  400ba4:	lea    0x1(%rbx),%edx
  400ba7:	mov    %edx,0x2014d3(%rip)        # 602080 <locked>
  400bad:	mov    0x2014cd(%rip),%edi        # 602080 <locked>
  400bb3:	lea    0x1(%rdi),%edx
  400bb6:	mov    %edx,0x2014c4(%rip)        # 602080 <locked>
  400bbc:	mov    0x2014be(%rip),%ebx        # 602080 <locked>
  400bc2:	lea    0x1(%rbx),%edx
  400bc5:	mov    %edx,0x2014b5(%rip)        # 602080 <locked>
  400bcb:	mov    0x2014af(%rip),%edi        # 602080 <locked>
  400bd1:	lea    0x1(%rdi),%edx
  400bd4:	mov    %edx,0x2014a6(%rip)        # 602080 <locked>
  400bda:	mov    0x2014a0(%rip),%ebx        # 602080 <locked>
  400be0:	lea    0x1(%rbx),%edx
  400be3:	mov    %edx,0x201497(%rip)        # 602080 <locked>
  400be9:	mov    0x201491(%rip),%esi        # 602080 <locked>
  400bef:	lea    0x1(%rsi),%edx
  400bf2:	mov    %edx,0x201488(%rip)        # 602080 <locked>
  400bf8:	mov    0x201482(%rip),%edi        # 602080 <locked>
  400bfe:	lea    0x1(%rdi),%edx
  400c01:	mov    %edx,0x201479(%rip)        # 602080 <locked>
  400c07:	mov    0x201473(%rip),%ebx        # 602080 <locked>
  400c0d:	lea    0x1(%rbx),%edx
  400c10:	mov    %edx,0x20146a(%rip)        # 602080 <locked>
  400c16:	mov    0x201464(%rip),%esi        # 602080 <locked>
  400c1c:	lea    0x1(%rsi),%edx
  400c1f:	mov    %edx,0x20145b(%rip)        # 602080 <locked>
  400c25:	mov    0x201455(%rip),%edi        # 602080 <locked>
  400c2b:	lea    0x1(%rdi),%edx
  400c2e:	mov    %edx,0x20144c(%rip)        # 602080 <locked>
  400c34:	mov    0x201446(%rip),%esi        # 602080 <locked>
  400c3a:	cmp    $0xa,%esi
  400c3d:	jne    400d0e <thread+0x1de>
  400c43:	mov    0x201437(%rip),%ebx        # 602080 <locked>
  400c49:	lea    -0x1(%rbx),%edx
  400c4c:	mov    %edx,0x20142e(%rip)        # 602080 <locked>
  400c52:	mov    0x201428(%rip),%esi        # 602080 <locked>
  400c58:	lea    -0x1(%rsi),%edx
  400c5b:	mov    %edx,0x20141f(%rip)        # 602080 <locked>
  400c61:	mov    0x201419(%rip),%edi        # 602080 <locked>
  400c67:	lea    -0x1(%rdi),%edx
  400c6a:	mov    %edx,0x201410(%rip)        # 602080 <locked>
  400c70:	mov    0x20140a(%rip),%ebx        # 602080 <locked>
  400c76:	lea    -0x1(%rbx),%edx
  400c79:	mov    %edx,0x201401(%rip)        # 602080 <locked>
  400c7f:	mov    0x2013fb(%rip),%esi        # 602080 <locked>
  400c85:	lea    -0x1(%rsi),%edx
  400c88:	mov    %edx,0x2013f2(%rip)        # 602080 <locked>
  400c8e:	mov    0x2013ec(%rip),%edi        # 602080 <locked>
  400c94:	lea    -0x1(%rdi),%edx
  400c97:	mov    %edx,0x2013e3(%rip)        # 602080 <locked>
  400c9d:	mov    0x2013dd(%rip),%ebx        # 602080 <locked>
  400ca3:	lea    -0x1(%rbx),%edx
  400ca6:	mov    %edx,0x2013d4(%rip)        # 602080 <locked>
  400cac:	mov    0x2013ce(%rip),%esi        # 602080 <locked>
  400cb2:	lea    -0x1(%rsi),%edx
  400cb5:	mov    %edx,0x2013c5(%rip)        # 602080 <locked>
  400cbb:	mov    0x2013bf(%rip),%edi        # 602080 <locked>
  400cc1:	lea    -0x1(%rdi),%edx
  400cc4:	mov    %edx,0x2013b6(%rip)        # 602080 <locked>
  400cca:	mov    0x2013b0(%rip),%ebx        # 602080 <locked>
  400cd0:	lea    -0x1(%rbx),%edx
  400cd3:	mov    %edx,0x2013a7(%rip)        # 602080 <locked>
  400cd9:	movl   $0x1,(%rax)
  400cdf:	lock decl (%rax)
  400ce2:	jns    400ced <thread+0x1bd>
  400ce4:	pause  
  400ce6:	cmpl   $0x0,(%rax)
  400ce9:	jle    400ce4 <thread+0x1b4>
  400ceb:	jmp    400cdf <thread+0x1af>
  400ced:	mov    0x20138d(%rip),%esi        # 602080 <locked>
  400cf3:	test   %esi,%esi
  400cf5:	jne    400d1c <thread+0x1ec>
  400cf7:	movl   $0x1,(%rax)
  400cfd:	sub    $0x1,%ecx
  400d00:	jne    400b90 <thread+0x60>
  400d06:	sub    $0xffffffffffffff80,%rsp
  400d0a:	xor    %eax,%eax
  400d0c:	pop    %rbx
  400d0d:	retq   
  400d0e:	lea    0xdb(%rip),%rdi        # 400df0 <__dso_handle+0x28>
  400d15:	xor    %eax,%eax
  400d17:	callq  400a80 <ck_error>
  400d1c:	lea    0xf5(%rip),%rdi        # 400e18 <__dso_handle+0x50>
  400d23:	xor    %eax,%eax
  400d25:	callq  400a80 <ck_error>
  400d2a:	lea    0x9f(%rip),%rdi        # 400dd0 <__dso_handle+0x8>
  400d31:	callq  400790 <perror@plt>
  400d36:	mov    $0x1,%edi
  400d3b:	callq  4007c0 <exit@plt>

0000000000400d40 <__libc_csu_init>:
  400d40:	push   %r15
  400d42:	push   %r14
  400d44:	mov    %edi,%r15d
  400d47:	push   %r13
  400d49:	push   %r12
  400d4b:	lea    0x20108e(%rip),%r12        # 601de0 <__frame_dummy_init_array_entry>
  400d52:	push   %rbp
  400d53:	lea    0x20108e(%rip),%rbp        # 601de8 <__init_array_end>
  400d5a:	push   %rbx
  400d5b:	mov    %rsi,%r14
  400d5e:	mov    %rdx,%r13
  400d61:	sub    %r12,%rbp
  400d64:	sub    $0x8,%rsp
  400d68:	sar    $0x3,%rbp
  400d6c:	callq  400710 <_init>
  400d71:	test   %rbp,%rbp
  400d74:	je     400d96 <__libc_csu_init+0x56>
  400d76:	xor    %ebx,%ebx
  400d78:	nopl   0x0(%rax,%rax,1)
  400d80:	mov    %r13,%rdx
  400d83:	mov    %r14,%rsi
  400d86:	mov    %r15d,%edi
  400d89:	callq  *(%r12,%rbx,8)
  400d8d:	add    $0x1,%rbx
  400d91:	cmp    %rbx,%rbp
  400d94:	jne    400d80 <__libc_csu_init+0x40>
  400d96:	add    $0x8,%rsp
  400d9a:	pop    %rbx
  400d9b:	pop    %rbp
  400d9c:	pop    %r12
  400d9e:	pop    %r13
  400da0:	pop    %r14
  400da2:	pop    %r15
  400da4:	retq   
  400da5:	nop
  400da6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400db0 <__libc_csu_fini>:
  400db0:	repz retq 

Disassembly of section .fini:

0000000000400db4 <_fini>:
  400db4:	sub    $0x8,%rsp
  400db8:	add    $0x8,%rsp
  400dbc:	retq   
