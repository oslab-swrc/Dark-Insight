// TC_OUT consumer,0x400b83,0x400b8b,0x0(0x6020c8)
// TC_OUT consumer,0x400ba8,0x400bd4,0x0(%r13)
// TC_OUT consumer,0x400bce,0x400bd8,0x0(%r13)
// TC_OUT consumer,0x400bf0,0x400c1f,0x0(%r13)
// TC_OUT consumer,0x400c19,0x400c23,0x0(%r13)
// TC_OUT main,0x400878,0x4008bf,0x0(0x6020c8)
ck_sequence:     file format elf64-x86-64


Disassembly of section .init:

00000000004006f0 <_init>:
  4006f0:	sub    $0x8,%rsp
  4006f4:	mov    0x2018f5(%rip),%rax        # 601ff0 <_DYNAMIC+0x1e8>
  4006fb:	test   %rax,%rax
  4006fe:	je     400702 <_init+0x12>
  400700:	callq  *%rax
  400702:	add    $0x8,%rsp
  400706:	retq   

Disassembly of section .plt:

0000000000400710 <pthread_create@plt-0x10>:
  400710:	pushq  0x2018f2(%rip)        # 602008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400716:	jmpq   *0x2018f4(%rip)        # 602010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40071c:	nopl   0x0(%rax)

0000000000400720 <pthread_create@plt>:
  400720:	jmpq   *0x2018f2(%rip)        # 602018 <_GLOBAL_OFFSET_TABLE_+0x18>
  400726:	pushq  $0x0
  40072b:	jmpq   400710 <_init+0x20>

0000000000400730 <printf@plt>:
  400730:	jmpq   *0x2018ea(%rip)        # 602020 <_GLOBAL_OFFSET_TABLE_+0x20>
  400736:	pushq  $0x1
  40073b:	jmpq   400710 <_init+0x20>

0000000000400740 <sched_setaffinity@plt>:
  400740:	jmpq   *0x2018e2(%rip)        # 602028 <_GLOBAL_OFFSET_TABLE_+0x28>
  400746:	pushq  $0x2
  40074b:	jmpq   400710 <_init+0x20>

0000000000400750 <fprintf@plt>:
  400750:	jmpq   *0x2018da(%rip)        # 602030 <_GLOBAL_OFFSET_TABLE_+0x30>
  400756:	pushq  $0x3
  40075b:	jmpq   400710 <_init+0x20>

0000000000400760 <syscall@plt>:
  400760:	jmpq   *0x2018d2(%rip)        # 602038 <_GLOBAL_OFFSET_TABLE_+0x38>
  400766:	pushq  $0x4
  40076b:	jmpq   400710 <_init+0x20>

0000000000400770 <strtol@plt>:
  400770:	jmpq   *0x2018ca(%rip)        # 602040 <_GLOBAL_OFFSET_TABLE_+0x40>
  400776:	pushq  $0x5
  40077b:	jmpq   400710 <_init+0x20>

0000000000400780 <malloc@plt>:
  400780:	jmpq   *0x2018c2(%rip)        # 602048 <_GLOBAL_OFFSET_TABLE_+0x48>
  400786:	pushq  $0x6
  40078b:	jmpq   400710 <_init+0x20>

0000000000400790 <perror@plt>:
  400790:	jmpq   *0x2018ba(%rip)        # 602050 <_GLOBAL_OFFSET_TABLE_+0x50>
  400796:	pushq  $0x7
  40079b:	jmpq   400710 <_init+0x20>

00000000004007a0 <vfprintf@plt>:
  4007a0:	jmpq   *0x2018b2(%rip)        # 602058 <_GLOBAL_OFFSET_TABLE_+0x58>
  4007a6:	pushq  $0x8
  4007ab:	jmpq   400710 <_init+0x20>

00000000004007b0 <exit@plt>:
  4007b0:	jmpq   *0x2018aa(%rip)        # 602060 <_GLOBAL_OFFSET_TABLE_+0x60>
  4007b6:	pushq  $0x9
  4007bb:	jmpq   400710 <_init+0x20>

Disassembly of section .text:

00000000004007c0 <main>:
  4007c0:	cmp    $0x3,%edi
  4007c3:	push   %r14
  4007c5:	push   %r13
  4007c7:	push   %r12
  4007c9:	push   %rbp
  4007ca:	push   %rbx
  4007cb:	jne    400904 <main+0x144>
  4007d1:	mov    0x8(%rsi),%rdi
  4007d5:	mov    %rsi,%rbp
  4007d8:	mov    $0xa,%edx
  4007dd:	xor    %esi,%esi
  4007df:	callq  400770 <strtol@plt>
  4007e4:	test   %eax,%eax
  4007e6:	mov    %rax,%r12
  4007e9:	mov    %eax,%r13d
  4007ec:	jle    4008f6 <main+0x136>
  4007f2:	movslq %eax,%rdi
  4007f5:	shl    $0x3,%rdi
  4007f9:	callq  400780 <malloc@plt>
  4007fe:	test   %rax,%rax
  400801:	mov    %rax,%rbx
  400804:	je     4008e8 <main+0x128>
  40080a:	mov    0x10(%rbp),%rdi
  40080e:	mov    $0xa,%edx
  400813:	xor    %esi,%esi
  400815:	lea    0x304(%rip),%r14        # 400b20 <consumer>
  40081c:	xor    %ebp,%ebp
  40081e:	callq  400770 <strtol@plt>
  400823:	movl   $0x0,0x201897(%rip)        # 6020c4 <affinerator+0x4>
  40082d:	mov    %eax,0x20188d(%rip)        # 6020c0 <affinerator>
  400833:	nopl   0x0(%rax,%rax,1)
  400838:	xor    %ecx,%ecx
  40083a:	xor    %esi,%esi
  40083c:	mov    %r14,%rdx
  40083f:	mov    %rbx,%rdi
  400842:	callq  400720 <pthread_create@plt>
  400847:	test   %eax,%eax
  400849:	jne    4008d8 <main+0x118>
  40084f:	add    $0x1,%ebp
  400852:	add    $0x8,%rbx
  400856:	cmp    %r13d,%ebp
  400859:	jne    400838 <main+0x78>
  40085b:	lea    0x20189e(%rip),%rcx        # 602100 <seqlock>
  400862:	lea    0x2018d7(%rip),%r8        # 602140 <global>
  400869:	mov    $0x3e8,%edx
  40086e:	mov    $0x1,%edi
  400873:	xor    %esi,%esi
  400875:	nopl   (%rax)
  400878:	mov    0x201882(%rip),%eax        # 602100 <seqlock>
  40087e:	add    $0x1,%eax
  400881:	mov    %eax,(%rcx)
  400883:	lea    0x3e8(%rsi),%eax
  400889:	mov    %esi,(%r8)
  40088c:	mov    %edx,0x2018b6(%rip)        # 602148 <global+0x8>
  400892:	mov    %eax,0x2018ac(%rip)        # 602144 <global+0x4>
  400898:	mov    0x201862(%rip),%eax        # 602100 <seqlock>
  40089e:	add    $0x1,%eax
  4008a1:	mov    %eax,(%rcx)
  4008a3:	test   %dil,%dil
  4008a6:	je     4008af <main+0xef>
  4008a8:	mov    %r12d,0x201819(%rip)        # 6020c8 <barrier>
  4008af:	add    $0x2,%esi
  4008b2:	mov    0x201810(%rip),%eax        # 6020c8 <barrier>
  4008b8:	xor    %edi,%edi
  4008ba:	add    $0x4,%edx
  4008bd:	test   %eax,%eax
  4008bf:	jne    400878 <main+0xb8>
  4008c1:	lea    0x5c5(%rip),%rdi        # 400e8d <__dso_handle+0x175>
  4008c8:	callq  400730 <printf@plt>
  4008cd:	pop    %rbx
  4008ce:	xor    %eax,%eax
  4008d0:	pop    %rbp
  4008d1:	pop    %r12
  4008d3:	pop    %r13
  4008d5:	pop    %r14
  4008d7:	retq   
  4008d8:	lea    0x579(%rip),%rdi        # 400e58 <__dso_handle+0x140>
  4008df:	mov    %ebp,%esi
  4008e1:	xor    %eax,%eax
  4008e3:	callq  400a20 <ck_error>
  4008e8:	lea    0x539(%rip),%rdi        # 400e28 <__dso_handle+0x110>
  4008ef:	xor    %eax,%eax
  4008f1:	callq  400a20 <ck_error>
  4008f6:	lea    0x4f3(%rip),%rdi        # 400df0 <__dso_handle+0xd8>
  4008fd:	xor    %eax,%eax
  4008ff:	callq  400a20 <ck_error>
  400904:	lea    0x4a5(%rip),%rdi        # 400db0 <__dso_handle+0x98>
  40090b:	xor    %eax,%eax
  40090d:	callq  400a20 <ck_error>
  400912:	nopw   %cs:0x0(%rax,%rax,1)
  40091c:	nopl   0x0(%rax)

0000000000400920 <_start>:
  400920:	xor    %ebp,%ebp
  400922:	mov    %rdx,%r9
  400925:	pop    %rsi
  400926:	mov    %rsp,%rdx
  400929:	and    $0xfffffffffffffff0,%rsp
  40092d:	push   %rax
  40092e:	push   %rsp
  40092f:	mov    $0x400d00,%r8
  400936:	mov    $0x400c90,%rcx
  40093d:	mov    $0x4007c0,%rdi
  400944:	callq  *0x20169e(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  40094a:	hlt    
  40094b:	nopl   0x0(%rax,%rax,1)

0000000000400950 <deregister_tm_clones>:
  400950:	mov    $0x602077,%eax
  400955:	push   %rbp
  400956:	sub    $0x602070,%rax
  40095c:	cmp    $0xe,%rax
  400960:	mov    %rsp,%rbp
  400963:	jbe    400980 <deregister_tm_clones+0x30>
  400965:	mov    $0x0,%eax
  40096a:	test   %rax,%rax
  40096d:	je     400980 <deregister_tm_clones+0x30>
  40096f:	pop    %rbp
  400970:	mov    $0x602070,%edi
  400975:	jmpq   *%rax
  400977:	nopw   0x0(%rax,%rax,1)
  400980:	pop    %rbp
  400981:	retq   
  400982:	nopl   0x0(%rax)
  400986:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400990 <register_tm_clones>:
  400990:	mov    $0x602070,%esi
  400995:	push   %rbp
  400996:	sub    $0x602070,%rsi
  40099d:	sar    $0x3,%rsi
  4009a1:	mov    %rsp,%rbp
  4009a4:	mov    %rsi,%rax
  4009a7:	shr    $0x3f,%rax
  4009ab:	add    %rax,%rsi
  4009ae:	sar    %rsi
  4009b1:	je     4009c8 <register_tm_clones+0x38>
  4009b3:	mov    $0x0,%eax
  4009b8:	test   %rax,%rax
  4009bb:	je     4009c8 <register_tm_clones+0x38>
  4009bd:	pop    %rbp
  4009be:	mov    $0x602070,%edi
  4009c3:	jmpq   *%rax
  4009c5:	nopl   (%rax)
  4009c8:	pop    %rbp
  4009c9:	retq   
  4009ca:	nopw   0x0(%rax,%rax,1)

00000000004009d0 <__do_global_dtors_aux>:
  4009d0:	cmpb   $0x0,0x2016a9(%rip)        # 602080 <completed.6917>
  4009d7:	jne    4009ea <__do_global_dtors_aux+0x1a>
  4009d9:	push   %rbp
  4009da:	mov    %rsp,%rbp
  4009dd:	callq  400950 <deregister_tm_clones>
  4009e2:	pop    %rbp
  4009e3:	movb   $0x1,0x201696(%rip)        # 602080 <completed.6917>
  4009ea:	repz retq 
  4009ec:	nopl   0x0(%rax)

00000000004009f0 <frame_dummy>:
  4009f0:	mov    $0x601e00,%edi
  4009f5:	cmpq   $0x0,(%rdi)
  4009f9:	jne    400a00 <frame_dummy+0x10>
  4009fb:	jmp    400990 <register_tm_clones>
  4009fd:	nopl   (%rax)
  400a00:	mov    $0x0,%eax
  400a05:	test   %rax,%rax
  400a08:	je     4009fb <frame_dummy+0xb>
  400a0a:	push   %rbp
  400a0b:	mov    %rsp,%rbp
  400a0e:	callq  *%rax
  400a10:	pop    %rbp
  400a11:	jmpq   400990 <register_tm_clones>
  400a16:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400a20 <ck_error>:
  400a20:	sub    $0xd8,%rsp
  400a27:	test   %al,%al
  400a29:	mov    %rsi,0x28(%rsp)
  400a2e:	mov    %rdx,0x30(%rsp)
  400a33:	mov    %rcx,0x38(%rsp)
  400a38:	mov    %r8,0x40(%rsp)
  400a3d:	mov    %r9,0x48(%rsp)
  400a42:	je     400a7b <ck_error+0x5b>
  400a44:	movaps %xmm0,0x50(%rsp)
  400a49:	movaps %xmm1,0x60(%rsp)
  400a4e:	movaps %xmm2,0x70(%rsp)
  400a53:	movaps %xmm3,0x80(%rsp)
  400a5b:	movaps %xmm4,0x90(%rsp)
  400a63:	movaps %xmm5,0xa0(%rsp)
  400a6b:	movaps %xmm6,0xb0(%rsp)
  400a73:	movaps %xmm7,0xc0(%rsp)
  400a7b:	lea    0xe0(%rsp),%rax
  400a83:	mov    %rdi,%rsi
  400a86:	lea    0x8(%rsp),%rdx
  400a8b:	mov    %rax,0x10(%rsp)
  400a90:	lea    0x20(%rsp),%rax
  400a95:	movl   $0x8,0x8(%rsp)
  400a9d:	movl   $0x30,0xc(%rsp)
  400aa5:	mov    %rax,0x18(%rsp)
  400aaa:	mov    0x201547(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400ab1:	mov    (%rax),%rdi
  400ab4:	callq  4007a0 <vfprintf@plt>
  400ab9:	mov    $0x1,%edi
  400abe:	callq  4007b0 <exit@plt>
  400ac3:	nopl   (%rax)
  400ac6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400ad0 <validate>:
  400ad0:	sub    $0x8,%rsp
  400ad4:	mov    (%rdi),%edx
  400ad6:	mov    0x4(%rdi),%eax
  400ad9:	lea    0x3e8(%rdx),%r8d
  400ae0:	cmp    %r8d,%eax
  400ae3:	jne    400af6 <validate+0x26>
  400ae5:	mov    0x8(%rdi),%esi
  400ae8:	lea    (%rax,%rdx,1),%r8d
  400aec:	cmp    %r8d,%esi
  400aef:	jne    400b0b <validate+0x3b>
  400af1:	add    $0x8,%rsp
  400af5:	retq   
  400af6:	lea    0x223(%rip),%rdi        # 400d20 <__dso_handle+0x8>
  400afd:	mov    %eax,%esi
  400aff:	mov    $0x3e8,%ecx
  400b04:	xor    %eax,%eax
  400b06:	callq  400a20 <ck_error>
  400b0b:	lea    0x246(%rip),%rdi        # 400d58 <__dso_handle+0x40>
  400b12:	mov    %eax,%ecx
  400b14:	xor    %eax,%eax
  400b16:	callq  400a20 <ck_error>
  400b1b:	nopl   0x0(%rax,%rax,1)

0000000000400b20 <consumer>:
  400b20:	push   %r15
  400b22:	push   %r14
  400b24:	push   %r13
  400b26:	push   %r12
  400b28:	push   %rbp
  400b29:	push   %rbx
  400b2a:	sub    $0x88,%rsp
  400b31:	mov    0x201589(%rip),%edx        # 6020c0 <affinerator>
  400b37:	lock xadd %edx,0x201585(%rip)        # 6020c4 <affinerator+0x4>
  400b3f:	xor    %eax,%eax
  400b41:	mov    $0x10,%ecx
  400b46:	mov    %rsp,%rdi
  400b49:	rep stos %rax,%es:(%rdi)
  400b4c:	and    $0x3,%edx
  400b4f:	mov    $0x1,%eax
  400b54:	mov    $0xba,%edi
  400b59:	mov    %edx,%ecx
  400b5b:	shl    %cl,%rax
  400b5e:	mov    %rax,(%rsp)
  400b62:	xor    %eax,%eax
  400b64:	callq  400760 <syscall@plt>
  400b69:	mov    %rsp,%rdx
  400b6c:	mov    $0x80,%esi
  400b71:	mov    %eax,%edi
  400b73:	callq  400740 <sched_setaffinity@plt>
  400b78:	test   %eax,%eax
  400b7a:	jne    400c6f <consumer+0x14f>
  400b80:	mov    %rsp,%rbp
  400b83:	mov    0x20153f(%rip),%eax        # 6020c8 <barrier>
  400b89:	test   %eax,%eax
  400b8b:	je     400b83 <consumer+0x63>
  400b8d:	mov    $0xf4240,%ebx
  400b92:	xor    %r12d,%r12d
  400b95:	lea    0x201564(%rip),%r13        # 602100 <seqlock>
  400b9c:	lea    0x20159d(%rip),%r14        # 602140 <global>
  400ba3:	jmp    400bce <consumer+0xae>
  400ba5:	nopl   (%rax)
  400ba8:	mov    (%r14),%edx
  400bab:	mov    %edx,(%rsp)
  400bae:	mov    0x201590(%rip),%edx        # 602144 <global+0x4>
  400bb4:	mov    %edx,0x4(%rsp)
  400bb8:	mov    0x20158a(%rip),%edx        # 602148 <global+0x8>
  400bbe:	mov    %edx,0x8(%rsp)
  400bc2:	add    $0x1,%r12d
  400bc6:	mov    0x0(%r13),%edx
  400bca:	cmp    %eax,%edx
  400bcc:	je     400be0 <consumer+0xc0>
  400bce:	mov    0x0(%r13),%eax
  400bd2:	test   $0x1,%al
  400bd4:	je     400ba8 <consumer+0x88>
  400bd6:	pause  
  400bd8:	jmp    400bce <consumer+0xae>
  400bda:	nopw   0x0(%rax,%rax,1)
  400be0:	mov    %rbp,%rdi
  400be3:	mov    %r12d,%r15d
  400be6:	callq  400ad0 <validate>
  400beb:	jmp    400c19 <consumer+0xf9>
  400bed:	nopl   (%rax)
  400bf0:	mov    (%r14),%edx
  400bf3:	mov    %edx,(%rsp)
  400bf6:	mov    0x201548(%rip),%edx        # 602144 <global+0x4>
  400bfc:	mov    %edx,0x4(%rsp)
  400c00:	mov    0x201542(%rip),%edx        # 602148 <global+0x8>
  400c06:	mov    %edx,0x8(%rsp)
  400c0a:	add    $0x1,%r12d
  400c0e:	mov    0x0(%r13),%edx
  400c12:	cmp    %eax,%edx
  400c14:	je     400c28 <consumer+0x108>
  400c16:	mov    %r12d,%r15d
  400c19:	mov    0x0(%r13),%eax
  400c1d:	test   $0x1,%al
  400c1f:	je     400bf0 <consumer+0xd0>
  400c21:	pause  
  400c23:	jmp    400c19 <consumer+0xf9>
  400c25:	nopl   (%rax)
  400c28:	mov    %rbp,%rdi
  400c2b:	callq  400ad0 <validate>
  400c30:	sub    $0x1,%ebx
  400c33:	jne    400bce <consumer+0xae>
  400c35:	mov    0x2013bc(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400c3c:	lea    -0xf423f(%r15),%edx
  400c43:	lea    0x236(%rip),%rsi        # 400e80 <__dso_handle+0x168>
  400c4a:	mov    (%rax),%rdi
  400c4d:	xor    %eax,%eax
  400c4f:	callq  400750 <fprintf@plt>
  400c54:	lock decl 0x20146d(%rip)        # 6020c8 <barrier>
  400c5b:	add    $0x88,%rsp
  400c62:	xor    %eax,%eax
  400c64:	pop    %rbx
  400c65:	pop    %rbp
  400c66:	pop    %r12
  400c68:	pop    %r13
  400c6a:	pop    %r14
  400c6c:	pop    %r15
  400c6e:	retq   
  400c6f:	lea    0x11a(%rip),%rdi        # 400d90 <__dso_handle+0x78>
  400c76:	callq  400790 <perror@plt>
  400c7b:	mov    $0x1,%edi
  400c80:	callq  4007b0 <exit@plt>
  400c85:	nopw   %cs:0x0(%rax,%rax,1)
  400c8f:	nop

0000000000400c90 <__libc_csu_init>:
  400c90:	push   %r15
  400c92:	push   %r14
  400c94:	mov    %edi,%r15d
  400c97:	push   %r13
  400c99:	push   %r12
  400c9b:	lea    0x20114e(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400ca2:	push   %rbp
  400ca3:	lea    0x20114e(%rip),%rbp        # 601df8 <__init_array_end>
  400caa:	push   %rbx
  400cab:	mov    %rsi,%r14
  400cae:	mov    %rdx,%r13
  400cb1:	sub    %r12,%rbp
  400cb4:	sub    $0x8,%rsp
  400cb8:	sar    $0x3,%rbp
  400cbc:	callq  4006f0 <_init>
  400cc1:	test   %rbp,%rbp
  400cc4:	je     400ce6 <__libc_csu_init+0x56>
  400cc6:	xor    %ebx,%ebx
  400cc8:	nopl   0x0(%rax,%rax,1)
  400cd0:	mov    %r13,%rdx
  400cd3:	mov    %r14,%rsi
  400cd6:	mov    %r15d,%edi
  400cd9:	callq  *(%r12,%rbx,8)
  400cdd:	add    $0x1,%rbx
  400ce1:	cmp    %rbx,%rbp
  400ce4:	jne    400cd0 <__libc_csu_init+0x40>
  400ce6:	add    $0x8,%rsp
  400cea:	pop    %rbx
  400ceb:	pop    %rbp
  400cec:	pop    %r12
  400cee:	pop    %r13
  400cf0:	pop    %r14
  400cf2:	pop    %r15
  400cf4:	retq   
  400cf5:	nop
  400cf6:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400d00 <__libc_csu_fini>:
  400d00:	repz retq 

Disassembly of section .fini:

0000000000400d04 <_fini>:
  400d04:	sub    $0x8,%rsp
  400d08:	add    $0x8,%rsp
  400d0c:	retq   
