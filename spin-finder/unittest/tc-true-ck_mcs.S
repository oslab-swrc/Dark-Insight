// TC_OUT thread,0x400be8,0x400bf3,-0xb0(%rbp)
// TC_OUT thread,0x400d90,0x400d9b,-0xb0(%rbp)
// TC_OUT thread,0x400df0,0x400dfc,-0xa8(%rbp)
// TC_OUT thread,0x400e10,0x400e1c,-0xa8(%rbp)

ck_mcs:     file format elf64-x86-64


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
  400852:	lea    0x7e7(%rip),%rdi        # 401040 <__dso_handle+0x118>
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
  4008bc:	lea    0x821(%rip),%rdi        # 4010e4 <__dso_handle+0x1bc>
  4008c3:	mov    $0x5,%edx
  4008c8:	mov    $0x1,%esi
  4008cd:	xor    %ebx,%ebx
  4008cf:	callq  4007d0 <fwrite@plt>
  4008d4:	mov    0x0(%r13),%rcx
  4008d8:	lea    0x789(%rip),%rdi        # 401068 <__dso_handle+0x140>
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
  40091c:	lea    0x7c7(%rip),%rdi        # 4010ea <__dso_handle+0x1c2>
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
  40093d:	lea    0x75c(%rip),%rdi        # 4010a0 <__dso_handle+0x178>
  400944:	mov    %rbx,%rsi
  400947:	xor    %eax,%eax
  400949:	callq  400a80 <ck_error>
  40094e:	lea    0x6bb(%rip),%rdi        # 401010 <__dso_handle+0xe8>
  400955:	xor    %eax,%eax
  400957:	callq  400a80 <ck_error>
  40095c:	lea    0x675(%rip),%rdi        # 400fd8 <__dso_handle+0xb0>
  400963:	callq  400a80 <ck_error>
  400968:	lea    0x631(%rip),%rdi        # 400fa0 <__dso_handle+0x78>
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
  40098f:	mov    $0x400f10,%r8
  400996:	mov    $0x400ea0,%rcx
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
  400b30:	lea    0x8(%rsp),%r10
  400b35:	and    $0xffffffffffffffc0,%rsp
  400b39:	pushq  -0x8(%r10)
  400b3d:	push   %rbp
  400b3e:	mov    %rsp,%rbp
  400b41:	push   %r10
  400b43:	push   %rbx
  400b44:	sub    $0xa0,%rsp
  400b4b:	mov    0x201587(%rip),%edx        # 6020d8 <a>
  400b51:	lock xadd %edx,0x201583(%rip)        # 6020dc <a+0x4>
  400b59:	lea    -0xb0(%rbp),%rbx
  400b60:	xor    %eax,%eax
  400b62:	mov    $0x10,%ecx
  400b67:	and    $0x3,%edx
  400b6a:	mov    %rbx,%rdi
  400b6d:	rep stos %rax,%es:(%rdi)
  400b70:	mov    %edx,%ecx
  400b72:	mov    $0x1,%eax
  400b77:	mov    $0xba,%edi
  400b7c:	shl    %cl,%rax
  400b7f:	mov    %rax,-0xb0(%rbp)
  400b86:	xor    %eax,%eax
  400b88:	callq  400760 <syscall@plt>
  400b8d:	mov    %rbx,%rdx
  400b90:	mov    $0x80,%esi
  400b95:	mov    %eax,%edi
  400b97:	callq  400750 <sched_setaffinity@plt>
  400b9c:	test   %eax,%eax
  400b9e:	jne    400e51 <thread+0x321>
  400ba4:	lea    0x201515(%rip),%rcx        # 6020c0 <lock>
  400bab:	mov    $0xf4240,%edx
  400bb0:	movl   $0x1,-0xb0(%rbp)
  400bba:	movq   $0x0,-0xa8(%rbp)
  400bc5:	mov    %rbx,%rax
  400bc8:	xchg   %rax,0x2014f1(%rip)        # 6020c0 <lock>
  400bcf:	test   %rax,%rax
  400bd2:	je     400bf5 <thread+0xc5>
  400bd4:	mov    %rbx,0x8(%rax)
  400bd8:	mov    -0xb0(%rbp),%eax
  400bde:	cmp    $0x1,%eax
  400be1:	jne    400bf5 <thread+0xc5>
  400be3:	nopl   0x0(%rax,%rax,1)
  400be8:	pause  
  400bea:	mov    -0xb0(%rbp),%eax
  400bf0:	cmp    $0x1,%eax
  400bf3:	je     400be8 <thread+0xb8>
  400bf5:	mov    (%rcx),%rax
  400bf8:	test   %rax,%rax
  400bfb:	je     400e67 <thread+0x337>
  400c01:	mov    0x2014c9(%rip),%eax        # 6020d0 <locked>
  400c07:	add    $0x1,%eax
  400c0a:	mov    %eax,0x2014c0(%rip)        # 6020d0 <locked>
  400c10:	mov    0x2014ba(%rip),%eax        # 6020d0 <locked>
  400c16:	add    $0x1,%eax
  400c19:	mov    %eax,0x2014b1(%rip)        # 6020d0 <locked>
  400c1f:	mov    0x2014ab(%rip),%eax        # 6020d0 <locked>
  400c25:	add    $0x1,%eax
  400c28:	mov    %eax,0x2014a2(%rip)        # 6020d0 <locked>
  400c2e:	mov    0x20149c(%rip),%eax        # 6020d0 <locked>
  400c34:	add    $0x1,%eax
  400c37:	mov    %eax,0x201493(%rip)        # 6020d0 <locked>
  400c3d:	mov    0x20148d(%rip),%eax        # 6020d0 <locked>
  400c43:	add    $0x1,%eax
  400c46:	mov    %eax,0x201484(%rip)        # 6020d0 <locked>
  400c4c:	mov    0x20147e(%rip),%eax        # 6020d0 <locked>
  400c52:	add    $0x1,%eax
  400c55:	mov    %eax,0x201475(%rip)        # 6020d0 <locked>
  400c5b:	mov    0x20146f(%rip),%eax        # 6020d0 <locked>
  400c61:	add    $0x1,%eax
  400c64:	mov    %eax,0x201466(%rip)        # 6020d0 <locked>
  400c6a:	mov    0x201460(%rip),%eax        # 6020d0 <locked>
  400c70:	add    $0x1,%eax
  400c73:	mov    %eax,0x201457(%rip)        # 6020d0 <locked>
  400c79:	mov    0x201451(%rip),%eax        # 6020d0 <locked>
  400c7f:	add    $0x1,%eax
  400c82:	mov    %eax,0x201448(%rip)        # 6020d0 <locked>
  400c88:	mov    0x201442(%rip),%eax        # 6020d0 <locked>
  400c8e:	add    $0x1,%eax
  400c91:	mov    %eax,0x201439(%rip)        # 6020d0 <locked>
  400c97:	mov    0x201433(%rip),%esi        # 6020d0 <locked>
  400c9d:	cmp    $0xa,%esi
  400ca0:	jne    400e75 <thread+0x345>
  400ca6:	mov    0x201424(%rip),%eax        # 6020d0 <locked>
  400cac:	sub    $0x1,%eax
  400caf:	mov    %eax,0x20141b(%rip)        # 6020d0 <locked>
  400cb5:	mov    0x201415(%rip),%eax        # 6020d0 <locked>
  400cbb:	sub    $0x1,%eax
  400cbe:	mov    %eax,0x20140c(%rip)        # 6020d0 <locked>
  400cc4:	mov    0x201406(%rip),%eax        # 6020d0 <locked>
  400cca:	sub    $0x1,%eax
  400ccd:	mov    %eax,0x2013fd(%rip)        # 6020d0 <locked>
  400cd3:	mov    0x2013f7(%rip),%eax        # 6020d0 <locked>
  400cd9:	sub    $0x1,%eax
  400cdc:	mov    %eax,0x2013ee(%rip)        # 6020d0 <locked>
  400ce2:	mov    0x2013e8(%rip),%eax        # 6020d0 <locked>
  400ce8:	sub    $0x1,%eax
  400ceb:	mov    %eax,0x2013df(%rip)        # 6020d0 <locked>
  400cf1:	mov    0x2013d9(%rip),%eax        # 6020d0 <locked>
  400cf7:	sub    $0x1,%eax
  400cfa:	mov    %eax,0x2013d0(%rip)        # 6020d0 <locked>
  400d00:	mov    0x2013ca(%rip),%eax        # 6020d0 <locked>
  400d06:	sub    $0x1,%eax
  400d09:	mov    %eax,0x2013c1(%rip)        # 6020d0 <locked>
  400d0f:	mov    0x2013bb(%rip),%eax        # 6020d0 <locked>
  400d15:	sub    $0x1,%eax
  400d18:	mov    %eax,0x2013b2(%rip)        # 6020d0 <locked>
  400d1e:	mov    0x2013ac(%rip),%eax        # 6020d0 <locked>
  400d24:	sub    $0x1,%eax
  400d27:	mov    %eax,0x2013a3(%rip)        # 6020d0 <locked>
  400d2d:	mov    0x20139d(%rip),%eax        # 6020d0 <locked>
  400d33:	sub    $0x1,%eax
  400d36:	mov    %eax,0x201394(%rip)        # 6020d0 <locked>
  400d3c:	mov    -0xa8(%rbp),%rsi
  400d43:	test   %rsi,%rsi
  400d46:	mov    %rsi,%rax
  400d49:	je     400e00 <thread+0x2d0>
  400d4f:	movl   $0x0,(%rax)
  400d55:	movl   $0x1,-0xb0(%rbp)
  400d5f:	movq   $0x0,-0xa8(%rbp)
  400d6a:	mov    %rbx,%rax
  400d6d:	xchg   %rax,0x20134c(%rip)        # 6020c0 <lock>
  400d74:	test   %rax,%rax
  400d77:	je     400d9d <thread+0x26d>
  400d79:	mov    %rbx,0x8(%rax)
  400d7d:	mov    -0xb0(%rbp),%eax
  400d83:	cmp    $0x1,%eax
  400d86:	jne    400d9d <thread+0x26d>
  400d88:	nopl   0x0(%rax,%rax,1)
  400d90:	pause  
  400d92:	mov    -0xb0(%rbp),%eax
  400d98:	cmp    $0x1,%eax
  400d9b:	je     400d90 <thread+0x260>
  400d9d:	mov    0x20132d(%rip),%esi        # 6020d0 <locked>
  400da3:	test   %esi,%esi
  400da5:	jne    400e83 <thread+0x353>
  400dab:	mov    -0xa8(%rbp),%rsi
  400db2:	test   %rsi,%rsi
  400db5:	mov    %rsi,%rax
  400db8:	je     400de0 <thread+0x2b0>
  400dba:	movl   $0x0,(%rax)
  400dc0:	sub    $0x1,%edx
  400dc3:	jne    400bb0 <thread+0x80>
  400dc9:	add    $0xa0,%rsp
  400dd0:	xor    %eax,%eax
  400dd2:	pop    %rbx
  400dd3:	pop    %r10
  400dd5:	pop    %rbp
  400dd6:	lea    -0x8(%r10),%rsp
  400dda:	retq   
  400ddb:	nopl   0x0(%rax,%rax,1)
  400de0:	mov    (%rcx),%rax
  400de3:	cmp    %rbx,%rax
  400de6:	jne    400df2 <thread+0x2c2>
  400de8:	jmp    400e23 <thread+0x2f3>
  400dea:	nopw   0x0(%rax,%rax,1)
  400df0:	pause  
  400df2:	mov    -0xa8(%rbp),%rax
  400df9:	test   %rax,%rax
  400dfc:	je     400df0 <thread+0x2c0>
  400dfe:	jmp    400dba <thread+0x28a>
  400e00:	mov    (%rcx),%rax
  400e03:	cmp    %rbx,%rax
  400e06:	jne    400e12 <thread+0x2e2>
  400e08:	jmp    400e38 <thread+0x308>
  400e0a:	nopw   0x0(%rax,%rax,1)
  400e10:	pause  
  400e12:	mov    -0xa8(%rbp),%rax
  400e19:	test   %rax,%rax
  400e1c:	je     400e10 <thread+0x2e0>
  400e1e:	jmpq   400d4f <thread+0x21f>
  400e23:	mov    %rbx,%rax
  400e26:	lock cmpxchg %rsi,0x201291(%rip)        # 6020c0 <lock>
  400e2f:	sete   %al
  400e32:	test   %al,%al
  400e34:	jne    400dc0 <thread+0x290>
  400e36:	jmp    400df2 <thread+0x2c2>
  400e38:	mov    %rbx,%rax
  400e3b:	lock cmpxchg %rsi,0x20127c(%rip)        # 6020c0 <lock>
  400e44:	sete   %al
  400e47:	test   %al,%al
  400e49:	jne    400d55 <thread+0x225>
  400e4f:	jmp    400e12 <thread+0x2e2>
  400e51:	lea    0xd8(%rip),%rdi        # 400f30 <__dso_handle+0x8>
  400e58:	callq  400790 <perror@plt>
  400e5d:	mov    $0x1,%edi
  400e62:	callq  4007c0 <exit@plt>
  400e67:	lea    0x25a(%rip),%rdi        # 4010c8 <__dso_handle+0x1a0>
  400e6e:	xor    %eax,%eax
  400e70:	callq  400a80 <ck_error>
  400e75:	lea    0xd4(%rip),%rdi        # 400f50 <__dso_handle+0x28>
  400e7c:	xor    %eax,%eax
  400e7e:	callq  400a80 <ck_error>
  400e83:	lea    0xee(%rip),%rdi        # 400f78 <__dso_handle+0x50>
  400e8a:	xor    %eax,%eax
  400e8c:	callq  400a80 <ck_error>
  400e91:	nopw   %cs:0x0(%rax,%rax,1)
  400e9b:	nopl   0x0(%rax,%rax,1)

0000000000400ea0 <__libc_csu_init>:
  400ea0:	push   %r15
  400ea2:	push   %r14
  400ea4:	mov    %edi,%r15d
  400ea7:	push   %r13
  400ea9:	push   %r12
  400eab:	lea    0x200f2e(%rip),%r12        # 601de0 <__frame_dummy_init_array_entry>
  400eb2:	push   %rbp
  400eb3:	lea    0x200f2e(%rip),%rbp        # 601de8 <__init_array_end>
  400eba:	push   %rbx
  400ebb:	mov    %rsi,%r14
  400ebe:	mov    %rdx,%r13
  400ec1:	sub    %r12,%rbp
  400ec4:	sub    $0x8,%rsp
  400ec8:	sar    $0x3,%rbp
  400ecc:	callq  400710 <_init>
  400ed1:	test   %rbp,%rbp
  400ed4:	je     400ef6 <__libc_csu_init+0x56>
  400ed6:	xor    %ebx,%ebx
  400ed8:	nopl   0x0(%rax,%rax,1)
  400ee0:	mov    %r13,%rdx
  400ee3:	mov    %r14,%rsi
  400ee6:	mov    %r15d,%edi
  400ee9:	callq  *(%r12,%rbx,8)
  400eed:	add    $0x1,%rbx
  400ef1:	cmp    %rbx,%rbp
  400ef4:	jne    400ee0 <__libc_csu_init+0x40>
  400ef6:	add    $0x8,%rsp
  400efa:	pop    %rbx
  400efb:	pop    %rbp
  400efc:	pop    %r12
  400efe:	pop    %r13
  400f00:	pop    %r14
  400f02:	pop    %r15
  400f04:	retq   
  400f05:	nop
  400f06:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400f10 <__libc_csu_fini>:
  400f10:	repz retq 

Disassembly of section .fini:

0000000000400f14 <_fini>:
  400f14:	sub    $0x8,%rsp
  400f18:	add    $0x8,%rsp
  400f1c:	retq   
