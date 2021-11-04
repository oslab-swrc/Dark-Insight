// TC_OUT thread,0x400bb0,0x400bd1,0x0(%rdi)
// TC_OUT thread,0x400d40,0x400d61,0x0(%rdi)

ck_ticket_pb:     file format elf64-x86-64


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
  400852:	lea    0x71f(%rip),%rdi        # 400f78 <__dso_handle+0x120>
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
  4008bc:	lea    0x759(%rip),%rdi        # 40101c <__dso_handle+0x1c4>
  4008c3:	mov    $0x5,%edx
  4008c8:	mov    $0x1,%esi
  4008cd:	xor    %ebx,%ebx
  4008cf:	callq  4007d0 <fwrite@plt>
  4008d4:	mov    0x0(%r13),%rcx
  4008d8:	lea    0x6c1(%rip),%rdi        # 400fa0 <__dso_handle+0x148>
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
  40091c:	lea    0x6ff(%rip),%rdi        # 401022 <__dso_handle+0x1ca>
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
  40093d:	lea    0x694(%rip),%rdi        # 400fd8 <__dso_handle+0x180>
  400944:	mov    %rbx,%rsi
  400947:	xor    %eax,%eax
  400949:	callq  400a80 <ck_error>
  40094e:	lea    0x5f3(%rip),%rdi        # 400f48 <__dso_handle+0xf0>
  400955:	xor    %eax,%eax
  400957:	callq  400a80 <ck_error>
  40095c:	lea    0x5ad(%rip),%rdi        # 400f10 <__dso_handle+0xb8>
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
  400b7e:	jne    400dad <thread+0x27d>
  400b84:	lea    0x201535(%rip),%rdi        # 6020c0 <lock>
  400b8b:	mov    $0xf4240,%r8d
  400b91:	mov    $0x10000,%r9d
  400b97:	mov    %r9d,%eax
  400b9a:	lock xadd %eax,0x20151e(%rip)        # 6020c0 <lock>
  400ba2:	mov    %eax,%esi
  400ba4:	movzwl %ax,%eax
  400ba7:	shr    $0x10,%esi
  400baa:	cmp    %esi,%eax
  400bac:	je     400bd3 <thread+0xa3>
  400bae:	xchg   %ax,%ax
  400bb0:	pause  
  400bb2:	mov    (%rdi),%ecx
  400bb4:	movzwl %cx,%ecx
  400bb7:	mov    %esi,%edx
  400bb9:	xor    %eax,%eax
  400bbb:	sub    %ecx,%edx
  400bbd:	movzwl %dx,%edx
  400bc0:	test   %edx,%edx
  400bc2:	je     400bcf <thread+0x9f>
  400bc4:	nopl   0x0(%rax)
  400bc8:	add    $0x1,%eax
  400bcb:	cmp    %eax,%edx
  400bcd:	jne    400bc8 <thread+0x98>
  400bcf:	cmp    %ecx,%esi
  400bd1:	jne    400bb0 <thread+0x80>
  400bd3:	mov    (%rdi),%eax
  400bd5:	movzwl %ax,%edx
  400bd8:	shr    $0x10,%eax
  400bdb:	cmp    %eax,%edx
  400bdd:	je     400d9f <thread+0x26f>
  400be3:	mov    0x2014e7(%rip),%eax        # 6020d0 <locked>
  400be9:	add    $0x1,%eax
  400bec:	mov    %eax,0x2014de(%rip)        # 6020d0 <locked>
  400bf2:	mov    0x2014d8(%rip),%eax        # 6020d0 <locked>
  400bf8:	add    $0x1,%eax
  400bfb:	mov    %eax,0x2014cf(%rip)        # 6020d0 <locked>
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
  400c79:	mov    0x201451(%rip),%esi        # 6020d0 <locked>
  400c7f:	cmp    $0xa,%esi
  400c82:	jne    400d91 <thread+0x261>
  400c88:	mov    0x201442(%rip),%eax        # 6020d0 <locked>
  400c8e:	sub    $0x1,%eax
  400c91:	mov    %eax,0x201439(%rip)        # 6020d0 <locked>
  400c97:	mov    0x201433(%rip),%eax        # 6020d0 <locked>
  400c9d:	sub    $0x1,%eax
  400ca0:	mov    %eax,0x20142a(%rip)        # 6020d0 <locked>
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
  400d1e:	lock incw (%rdi)
  400d22:	mov    %r9d,%eax
  400d25:	lock xadd %eax,0x201393(%rip)        # 6020c0 <lock>
  400d2d:	mov    %eax,%esi
  400d2f:	movzwl %ax,%eax
  400d32:	shr    $0x10,%esi
  400d35:	cmp    %esi,%eax
  400d37:	je     400d63 <thread+0x233>
  400d39:	nopl   0x0(%rax)
  400d40:	pause  
  400d42:	mov    (%rdi),%ecx
  400d44:	movzwl %cx,%ecx
  400d47:	mov    %esi,%edx
  400d49:	xor    %eax,%eax
  400d4b:	sub    %ecx,%edx
  400d4d:	movzwl %dx,%edx
  400d50:	test   %edx,%edx
  400d52:	je     400d5f <thread+0x22f>
  400d54:	nopl   0x0(%rax)
  400d58:	add    $0x1,%eax
  400d5b:	cmp    %eax,%edx
  400d5d:	jne    400d58 <thread+0x228>
  400d5f:	cmp    %ecx,%esi
  400d61:	jne    400d40 <thread+0x210>
  400d63:	mov    0x201367(%rip),%esi        # 6020d0 <locked>
  400d69:	test   %esi,%esi
  400d6b:	jne    400d83 <thread+0x253>
  400d6d:	lock incw (%rdi)
  400d71:	sub    $0x1,%r8d
  400d75:	jne    400b97 <thread+0x67>
  400d7b:	sub    $0xffffffffffffff80,%rsp
  400d7f:	xor    %eax,%eax
  400d81:	pop    %rbx
  400d82:	retq   
  400d83:	lea    0x11e(%rip),%rdi        # 400ea8 <__dso_handle+0x50>
  400d8a:	xor    %eax,%eax
  400d8c:	callq  400a80 <ck_error>
  400d91:	lea    0xe8(%rip),%rdi        # 400e80 <__dso_handle+0x28>
  400d98:	xor    %eax,%eax
  400d9a:	callq  400a80 <ck_error>
  400d9f:	lea    0x25a(%rip),%rdi        # 401000 <__dso_handle+0x1a8>
  400da6:	xor    %eax,%eax
  400da8:	callq  400a80 <ck_error>
  400dad:	lea    0xac(%rip),%rdi        # 400e60 <__dso_handle+0x8>
  400db4:	callq  400790 <perror@plt>
  400db9:	mov    $0x1,%edi
  400dbe:	callq  4007c0 <exit@plt>
  400dc3:	nopw   %cs:0x0(%rax,%rax,1)
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
