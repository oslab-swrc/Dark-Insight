// TC_OUT thread,0x400b8c,0x400b99,0x0(0x602088)
// TC_OUT thread,0x400bb0,0x400bb6,0x0(%rdx)
// TC_OUT thread,0x400c00,0x400c0d,0x0(0x602088)
// TC_OUT thread,0x400c20,0x400c26,0x0(%rdx)
// TC_OUT thread,0x400d1c,0x400d29,0x0(0x602088)
// TC_OUT thread,0x400d40,0x400d46,0x0(%rdx)
// TC_OUT thread,0x400d88,0x400d93,0x0(0x602088)
// TC_OUT thread,0x400d8a,0x400dab,0x0(0x602088)

validate:     file format elf64-x86-64


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
  4007d0:	cmp    $0x3,%edi
  4007d3:	push   %r14
  4007d5:	push   %r13
  4007d7:	push   %r12
  4007d9:	push   %rbp
  4007da:	push   %rbx
  4007db:	jne    40094b <main+0x17b>
  4007e1:	mov    0x8(%rsi),%rdi
  4007e5:	mov    %rsi,%rbx
  4007e8:	mov    $0xa,%edx
  4007ed:	xor    %esi,%esi
  4007ef:	callq  400760 <strtol@plt>
  4007f4:	test   %eax,%eax
  4007f6:	mov    %eax,0x201894(%rip)        # 602090 <nthr>
  4007fc:	jle    40093d <main+0x16d>
  400802:	cltq   
  400804:	lea    0x0(,%rax,8),%rdi
  40080c:	callq  400770 <malloc@plt>
  400811:	test   %rax,%rax
  400814:	mov    %rax,%r12
  400817:	je     40092f <main+0x15f>
  40081d:	mov    0x10(%rbx),%rdi
  400821:	xor    %esi,%esi
  400823:	mov    $0xa,%edx
  400828:	xor    %ebx,%ebx
  40082a:	mov    %r12,%rbp
  40082d:	lea    0x2dc(%rip),%r14        # 400b10 <thread>
  400834:	callq  400760 <strtol@plt>
  400839:	mov    0x2017b8(%rip),%r13        # 601ff8 <_DYNAMIC+0x1f0>
  400840:	lea    0x729(%rip),%rdi        # 400f70 <__dso_handle+0xc8>
  400847:	mov    $0x26,%edx
  40084c:	mov    $0x1,%esi
  400851:	mov    %eax,0x201841(%rip)        # 602098 <a>
  400857:	mov    0x0(%r13),%rcx
  40085b:	callq  4007c0 <fwrite@plt>
  400860:	mov    0x20182a(%rip),%edx        # 602090 <nthr>
  400866:	test   %edx,%edx
  400868:	jle    400896 <main+0xc6>
  40086a:	nopw   0x0(%rax,%rax,1)
  400870:	xor    %ecx,%ecx
  400872:	xor    %esi,%esi
  400874:	mov    %r14,%rdx
  400877:	mov    %rbp,%rdi
  40087a:	callq  400730 <pthread_create@plt>
  40087f:	test   %eax,%eax
  400881:	jne    40091f <main+0x14f>
  400887:	add    $0x1,%ebx
  40088a:	add    $0x8,%rbp
  40088e:	cmp    %ebx,0x2017fc(%rip)        # 602090 <nthr>
  400894:	jg     400870 <main+0xa0>
  400896:	mov    0x0(%r13),%rcx
  40089a:	lea    0x79f(%rip),%rdi        # 401040 <__dso_handle+0x198>
  4008a1:	mov    $0x5,%edx
  4008a6:	mov    $0x1,%esi
  4008ab:	mov    $0x1,%ebx
  4008b0:	callq  4007c0 <fwrite@plt>
  4008b5:	mov    0x0(%r13),%rcx
  4008b9:	lea    0x6d8(%rip),%rdi        # 400f98 <__dso_handle+0xf0>
  4008c0:	mov    $0x37,%edx
  4008c5:	mov    $0x1,%esi
  4008ca:	callq  4007c0 <fwrite@plt>
  4008cf:	mov    0x2017bb(%rip),%eax        # 602090 <nthr>
  4008d5:	test   %eax,%eax
  4008d7:	jle    4008fa <main+0x12a>
  4008d9:	nopl   0x0(%rax)
  4008e0:	mov    -0x8(%r12,%rbx,8),%rdi
  4008e5:	xor    %esi,%esi
  4008e7:	callq  400790 <pthread_join@plt>
  4008ec:	mov    %ebx,%eax
  4008ee:	add    $0x1,%rbx
  4008f2:	cmp    %eax,0x201798(%rip)        # 602090 <nthr>
  4008f8:	jg     4008e0 <main+0x110>
  4008fa:	mov    0x0(%r13),%rcx
  4008fe:	lea    0x741(%rip),%rdi        # 401046 <__dso_handle+0x19e>
  400905:	mov    $0xe,%edx
  40090a:	mov    $0x1,%esi
  40090f:	callq  4007c0 <fwrite@plt>
  400914:	pop    %rbx
  400915:	xor    %eax,%eax
  400917:	pop    %rbp
  400918:	pop    %r12
  40091a:	pop    %r13
  40091c:	pop    %r14
  40091e:	retq   
  40091f:	lea    0x6aa(%rip),%rdi        # 400fd0 <__dso_handle+0x128>
  400926:	mov    %ebx,%esi
  400928:	xor    %eax,%eax
  40092a:	callq  400a60 <ck_error>
  40092f:	lea    0x60a(%rip),%rdi        # 400f40 <__dso_handle+0x98>
  400936:	xor    %eax,%eax
  400938:	callq  400a60 <ck_error>
  40093d:	lea    0x5c4(%rip),%rdi        # 400f08 <__dso_handle+0x60>
  400944:	xor    %eax,%eax
  400946:	callq  400a60 <ck_error>
  40094b:	lea    0x57e(%rip),%rdi        # 400ed0 <__dso_handle+0x28>
  400952:	xor    %eax,%eax
  400954:	callq  400a60 <ck_error>
  400959:	nopl   0x0(%rax)

0000000000400960 <_start>:
  400960:	xor    %ebp,%ebp
  400962:	mov    %rdx,%r9
  400965:	pop    %rsi
  400966:	mov    %rsp,%rdx
  400969:	and    $0xfffffffffffffff0,%rsp
  40096d:	push   %rax
  40096e:	push   %rsp
  40096f:	mov    $0x400e90,%r8
  400976:	mov    $0x400e20,%rcx
  40097d:	mov    $0x4007d0,%rdi
  400984:	callq  *0x20165e(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  40098a:	hlt    
  40098b:	nopl   0x0(%rax,%rax,1)

0000000000400990 <deregister_tm_clones>:
  400990:	mov    $0x602077,%eax
  400995:	push   %rbp
  400996:	sub    $0x602070,%rax
  40099c:	cmp    $0xe,%rax
  4009a0:	mov    %rsp,%rbp
  4009a3:	jbe    4009c0 <deregister_tm_clones+0x30>
  4009a5:	mov    $0x0,%eax
  4009aa:	test   %rax,%rax
  4009ad:	je     4009c0 <deregister_tm_clones+0x30>
  4009af:	pop    %rbp
  4009b0:	mov    $0x602070,%edi
  4009b5:	jmpq   *%rax
  4009b7:	nopw   0x0(%rax,%rax,1)
  4009c0:	pop    %rbp
  4009c1:	retq   
  4009c2:	nopl   0x0(%rax)
  4009c6:	nopw   %cs:0x0(%rax,%rax,1)

00000000004009d0 <register_tm_clones>:
  4009d0:	mov    $0x602070,%esi
  4009d5:	push   %rbp
  4009d6:	sub    $0x602070,%rsi
  4009dd:	sar    $0x3,%rsi
  4009e1:	mov    %rsp,%rbp
  4009e4:	mov    %rsi,%rax
  4009e7:	shr    $0x3f,%rax
  4009eb:	add    %rax,%rsi
  4009ee:	sar    %rsi
  4009f1:	je     400a08 <register_tm_clones+0x38>
  4009f3:	mov    $0x0,%eax
  4009f8:	test   %rax,%rax
  4009fb:	je     400a08 <register_tm_clones+0x38>
  4009fd:	pop    %rbp
  4009fe:	mov    $0x602070,%edi
  400a03:	jmpq   *%rax
  400a05:	nopl   (%rax)
  400a08:	pop    %rbp
  400a09:	retq   
  400a0a:	nopw   0x0(%rax,%rax,1)

0000000000400a10 <__do_global_dtors_aux>:
  400a10:	cmpb   $0x0,0x201659(%rip)        # 602070 <__TMC_END__>
  400a17:	jne    400a2a <__do_global_dtors_aux+0x1a>
  400a19:	push   %rbp
  400a1a:	mov    %rsp,%rbp
  400a1d:	callq  400990 <deregister_tm_clones>
  400a22:	pop    %rbp
  400a23:	movb   $0x1,0x201646(%rip)        # 602070 <__TMC_END__>
  400a2a:	repz retq 
  400a2c:	nopl   0x0(%rax)

0000000000400a30 <frame_dummy>:
  400a30:	mov    $0x601e00,%edi
  400a35:	cmpq   $0x0,(%rdi)
  400a39:	jne    400a40 <frame_dummy+0x10>
  400a3b:	jmp    4009d0 <register_tm_clones>
  400a3d:	nopl   (%rax)
  400a40:	mov    $0x0,%eax
  400a45:	test   %rax,%rax
  400a48:	je     400a3b <frame_dummy+0xb>
  400a4a:	push   %rbp
  400a4b:	mov    %rsp,%rbp
  400a4e:	callq  *%rax
  400a50:	pop    %rbp
  400a51:	jmpq   4009d0 <register_tm_clones>
  400a56:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a60 <ck_error>:
  400a60:	sub    $0xd8,%rsp
  400a67:	test   %al,%al
  400a69:	mov    %rsi,0x28(%rsp)
  400a6e:	mov    %rdx,0x30(%rsp)
  400a73:	mov    %rcx,0x38(%rsp)
  400a78:	mov    %r8,0x40(%rsp)
  400a7d:	mov    %r9,0x48(%rsp)
  400a82:	je     400abb <ck_error+0x5b>
  400a84:	movaps %xmm0,0x50(%rsp)
  400a89:	movaps %xmm1,0x60(%rsp)
  400a8e:	movaps %xmm2,0x70(%rsp)
  400a93:	movaps %xmm3,0x80(%rsp)
  400a9b:	movaps %xmm4,0x90(%rsp)
  400aa3:	movaps %xmm5,0xa0(%rsp)
  400aab:	movaps %xmm6,0xb0(%rsp)
  400ab3:	movaps %xmm7,0xc0(%rsp)
  400abb:	lea    0xe0(%rsp),%rax
  400ac3:	mov    %rdi,%rsi
  400ac6:	lea    0x8(%rsp),%rdx
  400acb:	mov    %rax,0x10(%rsp)
  400ad0:	lea    0x20(%rsp),%rax
  400ad5:	movl   $0x8,0x8(%rsp)
  400add:	movl   $0x30,0xc(%rsp)
  400ae5:	mov    %rax,0x18(%rsp)
  400aea:	mov    0x201507(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400af1:	mov    (%rax),%rdi
  400af4:	callq  4007a0 <vfprintf@plt>
  400af9:	mov    $0x1,%edi
  400afe:	callq  4007b0 <exit@plt>
  400b03:	nopl   (%rax)
  400b06:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b10 <thread>:
  400b10:	push   %rbx
  400b11:	add    $0xffffffffffffff80,%rsp
  400b15:	mov    0x20157d(%rip),%edx        # 602098 <a>
  400b1b:	lock xadd %edx,0x201579(%rip)        # 60209c <a+0x4>
  400b23:	xor    %eax,%eax
  400b25:	mov    $0x10,%ecx
  400b2a:	mov    %rsp,%rdi
  400b2d:	rep stos %rax,%es:(%rdi)
  400b30:	and    $0x3,%edx
  400b33:	mov    $0x1,%eax
  400b38:	mov    $0xba,%edi
  400b3d:	mov    %edx,%ecx
  400b3f:	shl    %cl,%rax
  400b42:	mov    %rax,(%rsp)
  400b46:	xor    %eax,%eax
  400b48:	callq  400750 <syscall@plt>
  400b4d:	mov    %rsp,%rdx
  400b50:	mov    $0x80,%esi
  400b55:	mov    %eax,%edi
  400b57:	callq  400740 <sched_setaffinity@plt>
  400b5c:	test   %eax,%eax
  400b5e:	jne    400e0a <thread+0x2fa>
  400b64:	mov    %rsp,%rbx
  400b67:	movl   $0x0,(%rsp)
  400b6e:	movq   $0x0,0x8(%rsp)
  400b77:	mov    $0x1,%eax
  400b7c:	xchg   %eax,0x201506(%rip)        # 602088 <lock+0x8>
  400b82:	cmp    $0x1,%eax
  400b85:	mov    $0x1,%edx
  400b8a:	jne    400b9b <thread+0x8b>
  400b8c:	pause  
  400b8e:	mov    %edx,%eax
  400b90:	xchg   %eax,0x2014f2(%rip)        # 602088 <lock+0x8>
  400b96:	cmp    $0x1,%eax
  400b99:	je     400b8c <thread+0x7c>
  400b9b:	mov    0x2014de(%rip),%rdx        # 602080 <lock>
  400ba2:	test   %rdx,%rdx
  400ba5:	jne    400bb2 <thread+0xa2>
  400ba7:	jmp    400bc1 <thread+0xb1>
  400ba9:	nopl   0x0(%rax)
  400bb0:	pause  
  400bb2:	mov    (%rdx),%eax
  400bb4:	test   %eax,%eax
  400bb6:	jne    400bb0 <thread+0xa0>
  400bb8:	mov    0x10(%rdx),%rdx
  400bbc:	test   %rdx,%rdx
  400bbf:	jne    400bb2 <thread+0xa2>
  400bc1:	mov    0x2014b8(%rip),%rax        # 602080 <lock>
  400bc8:	test   %rax,%rax
  400bcb:	mov    %rax,0x10(%rsp)
  400bd0:	je     400bd6 <thread+0xc6>
  400bd2:	mov    %rbx,0x8(%rax)
  400bd6:	mov    %rbx,0x2014a3(%rip)        # 602080 <lock>
  400bdd:	movl   $0x0,0x2014a1(%rip)        # 602088 <lock+0x8>
  400be7:	mov    $0xf4240,%esi
  400bec:	lea    0x20148d(%rip),%rdi        # 602080 <lock>
  400bf3:	mov    $0x1,%ecx
  400bf8:	jmp    400c02 <thread+0xf2>
  400bfa:	nopw   0x0(%rax,%rax,1)
  400c00:	pause  
  400c02:	mov    %ecx,%eax
  400c04:	xchg   %eax,0x20147e(%rip)        # 602088 <lock+0x8>
  400c0a:	cmp    $0x1,%eax
  400c0d:	je     400c00 <thread+0xf0>
  400c0f:	mov    (%rdi),%rdx
  400c12:	test   %rdx,%rdx
  400c15:	jne    400c22 <thread+0x112>
  400c17:	jmp    400c31 <thread+0x121>
  400c19:	nopl   0x0(%rax)
  400c20:	pause  
  400c22:	mov    (%rdx),%eax
  400c24:	test   %eax,%eax
  400c26:	jne    400c20 <thread+0x110>
  400c28:	mov    0x10(%rdx),%rdx
  400c2c:	test   %rdx,%rdx
  400c2f:	jne    400c22 <thread+0x112>
  400c31:	mov    0x20145d(%rip),%edx        # 602094 <locked>
  400c37:	test   %edx,%edx
  400c39:	jne    400df7 <thread+0x2e7>
  400c3f:	lock incl 0x20144e(%rip)        # 602094 <locked>
  400c46:	lock incl 0x201447(%rip)        # 602094 <locked>
  400c4d:	lock incl 0x201440(%rip)        # 602094 <locked>
  400c54:	lock incl 0x201439(%rip)        # 602094 <locked>
  400c5b:	lock incl 0x201432(%rip)        # 602094 <locked>
  400c62:	lock incl 0x20142b(%rip)        # 602094 <locked>
  400c69:	lock incl 0x201424(%rip)        # 602094 <locked>
  400c70:	lock incl 0x20141d(%rip)        # 602094 <locked>
  400c77:	mov    0x201417(%rip),%edx        # 602094 <locked>
  400c7d:	cmp    $0x8,%edx
  400c80:	jne    400dc5 <thread+0x2b5>
  400c86:	lock decl 0x201407(%rip)        # 602094 <locked>
  400c8d:	lock decl 0x201400(%rip)        # 602094 <locked>
  400c94:	lock decl 0x2013f9(%rip)        # 602094 <locked>
  400c9b:	lock decl 0x2013f2(%rip)        # 602094 <locked>
  400ca2:	lock decl 0x2013eb(%rip)        # 602094 <locked>
  400ca9:	lock decl 0x2013e4(%rip)        # 602094 <locked>
  400cb0:	lock decl 0x2013dd(%rip)        # 602094 <locked>
  400cb7:	lock decl 0x2013d6(%rip)        # 602094 <locked>
  400cbe:	mov    0x2013d0(%rip),%edx        # 602094 <locked>
  400cc4:	test   %edx,%edx
  400cc6:	jne    400db2 <thread+0x2a2>
  400ccc:	movl   $0x0,0x2013b2(%rip)        # 602088 <lock+0x8>
  400cd6:	mov    (%rsp),%eax
  400cd9:	test   %eax,%eax
  400cdb:	je     400d8a <thread+0x27a>
  400ce1:	add    $0x1,%eax
  400ce4:	mov    %eax,(%rsp)
  400ce7:	mov    0x2013a7(%rip),%edx        # 602094 <locked>
  400ced:	test   %edx,%edx
  400cef:	jne    400dd8 <thread+0x2c8>
  400cf5:	mov    (%rsp),%eax
  400cf8:	sub    $0x1,%eax
  400cfb:	mov    %eax,(%rsp)
  400cfe:	sub    $0x1,%esi
  400d01:	jne    400c02 <thread+0xf2>
  400d07:	mov    $0x1,%eax
  400d0c:	xchg   %eax,0x201376(%rip)        # 602088 <lock+0x8>
  400d12:	cmp    $0x1,%eax
  400d15:	mov    $0x1,%edx
  400d1a:	jne    400d2b <thread+0x21b>
  400d1c:	pause  
  400d1e:	mov    %edx,%eax
  400d20:	xchg   %eax,0x201362(%rip)        # 602088 <lock+0x8>
  400d26:	cmp    $0x1,%eax
  400d29:	je     400d1c <thread+0x20c>
  400d2b:	mov    0x20134e(%rip),%rdx        # 602080 <lock>
  400d32:	test   %rdx,%rdx
  400d35:	jne    400d42 <thread+0x232>
  400d37:	jmp    400d51 <thread+0x241>
  400d39:	nopl   0x0(%rax)
  400d40:	pause  
  400d42:	mov    (%rdx),%eax
  400d44:	test   %eax,%eax
  400d46:	jne    400d40 <thread+0x230>
  400d48:	mov    0x10(%rdx),%rdx
  400d4c:	test   %rdx,%rdx
  400d4f:	jne    400d42 <thread+0x232>
  400d51:	mov    0x10(%rsp),%rax
  400d56:	test   %rax,%rax
  400d59:	je     400d64 <thread+0x254>
  400d5b:	mov    0x8(%rsp),%rdx
  400d60:	mov    %rdx,0x8(%rax)
  400d64:	mov    0x8(%rsp),%rdx
  400d69:	test   %rdx,%rdx
  400d6c:	je     400deb <thread+0x2db>
  400d6e:	mov    %rax,0x10(%rdx)
  400d72:	movl   $0x0,0x20130c(%rip)        # 602088 <lock+0x8>
  400d7c:	sub    $0xffffffffffffff80,%rsp
  400d80:	xor    %eax,%eax
  400d82:	pop    %rbx
  400d83:	retq   
  400d84:	nopl   0x0(%rax)
  400d88:	pause  
  400d8a:	mov    0x2012f8(%rip),%eax        # 602088 <lock+0x8>
  400d90:	cmp    $0x1,%eax
  400d93:	je     400d88 <thread+0x278>
  400d95:	mov    %ecx,%eax
  400d97:	xchg   %eax,(%rsp)
  400d9a:	mov    0x2012e8(%rip),%eax        # 602088 <lock+0x8>
  400da0:	test   %eax,%eax
  400da2:	je     400dad <thread+0x29d>
  400da4:	movl   $0x0,(%rsp)
  400dab:	jmp    400d8a <thread+0x27a>
  400dad:	jmpq   400ce7 <thread+0x1d7>
  400db2:	lea    0x23f(%rip),%rdi        # 400ff8 <__dso_handle+0x150>
  400db9:	mov    $0x63,%esi
  400dbe:	xor    %eax,%eax
  400dc0:	callq  400a60 <ck_error>
  400dc5:	lea    0x244(%rip),%rdi        # 401010 <__dso_handle+0x168>
  400dcc:	mov    $0x55,%esi
  400dd1:	xor    %eax,%eax
  400dd3:	callq  400a60 <ck_error>
  400dd8:	lea    0x249(%rip),%rdi        # 401028 <__dso_handle+0x180>
  400ddf:	mov    $0x6c,%esi
  400de4:	xor    %eax,%eax
  400de6:	callq  400a60 <ck_error>
  400deb:	mov    %rax,0x20128e(%rip)        # 602080 <lock>
  400df2:	jmpq   400d72 <thread+0x262>
  400df7:	lea    0x1fa(%rip),%rdi        # 400ff8 <__dso_handle+0x150>
  400dfe:	mov    $0x47,%esi
  400e03:	xor    %eax,%eax
  400e05:	callq  400a60 <ck_error>
  400e0a:	lea    0x9f(%rip),%rdi        # 400eb0 <__dso_handle+0x8>
  400e11:	callq  400780 <perror@plt>
  400e16:	mov    $0x1,%edi
  400e1b:	callq  4007b0 <exit@plt>

0000000000400e20 <__libc_csu_init>:
  400e20:	push   %r15
  400e22:	push   %r14
  400e24:	mov    %edi,%r15d
  400e27:	push   %r13
  400e29:	push   %r12
  400e2b:	lea    0x200fbe(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400e32:	push   %rbp
  400e33:	lea    0x200fbe(%rip),%rbp        # 601df8 <__init_array_end>
  400e3a:	push   %rbx
  400e3b:	mov    %rsi,%r14
  400e3e:	mov    %rdx,%r13
  400e41:	sub    %r12,%rbp
  400e44:	sub    $0x8,%rsp
  400e48:	sar    $0x3,%rbp
  400e4c:	callq  400700 <_init>
  400e51:	test   %rbp,%rbp
  400e54:	je     400e76 <__libc_csu_init+0x56>
  400e56:	xor    %ebx,%ebx
  400e58:	nopl   0x0(%rax,%rax,1)
  400e60:	mov    %r13,%rdx
  400e63:	mov    %r14,%rsi
  400e66:	mov    %r15d,%edi
  400e69:	callq  *(%r12,%rbx,8)
  400e6d:	add    $0x1,%rbx
  400e71:	cmp    %rbx,%rbp
  400e74:	jne    400e60 <__libc_csu_init+0x40>
  400e76:	add    $0x8,%rsp
  400e7a:	pop    %rbx
  400e7b:	pop    %rbp
  400e7c:	pop    %r12
  400e7e:	pop    %r13
  400e80:	pop    %r14
  400e82:	pop    %r15
  400e84:	retq   
  400e85:	nop
  400e86:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400e90 <__libc_csu_fini>:
  400e90:	repz retq 

Disassembly of section .fini:

0000000000400e94 <_fini>:
  400e94:	sub    $0x8,%rsp
  400e98:	add    $0x8,%rsp
  400e9c:	retq   
