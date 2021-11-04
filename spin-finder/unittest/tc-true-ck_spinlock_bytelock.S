// TC_OUT thread,0x400b98,0x400ba2,0x0(0x60208c)
// TC_OUT thread,0x400bc0,0x400bca,0x0(0x602084)
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
  400840:	lea    0x649(%rip),%rdi        # 400e90 <__dso_handle+0xc8>
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
  40089a:	lea    0x6bf(%rip),%rdi        # 400f60 <__dso_handle+0x198>
  4008a1:	mov    $0x5,%edx
  4008a6:	mov    $0x1,%esi
  4008ab:	mov    $0x1,%ebx
  4008b0:	callq  4007c0 <fwrite@plt>
  4008b5:	mov    0x0(%r13),%rcx
  4008b9:	lea    0x5f8(%rip),%rdi        # 400eb8 <__dso_handle+0xf0>
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
  4008fe:	lea    0x661(%rip),%rdi        # 400f66 <__dso_handle+0x19e>
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
  40091f:	lea    0x5ca(%rip),%rdi        # 400ef0 <__dso_handle+0x128>
  400926:	mov    %ebx,%esi
  400928:	xor    %eax,%eax
  40092a:	callq  400a60 <ck_error>
  40092f:	lea    0x52a(%rip),%rdi        # 400e60 <__dso_handle+0x98>
  400936:	xor    %eax,%eax
  400938:	callq  400a60 <ck_error>
  40093d:	lea    0x4e4(%rip),%rdi        # 400e28 <__dso_handle+0x60>
  400944:	xor    %eax,%eax
  400946:	callq  400a60 <ck_error>
  40094b:	lea    0x49e(%rip),%rdi        # 400df0 <__dso_handle+0x28>
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
  40096f:	mov    $0x400db0,%r8
  400976:	mov    $0x400d40,%rcx
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
  400b15:	mov    0x20157d(%rip),%esi        # 602098 <a>
  400b1b:	lock xadd %esi,0x201579(%rip)        # 60209c <a+0x4>
  400b23:	xor    %eax,%eax
  400b25:	mov    $0x10,%ecx
  400b2a:	mov    %rsp,%rdi
  400b2d:	rep stos %rax,%es:(%rdi)
  400b30:	and    $0x3,%esi
  400b33:	mov    $0x1,%eax
  400b38:	mov    $0xba,%edi
  400b3d:	mov    %esi,%ecx
  400b3f:	shl    %cl,%rax
  400b42:	mov    %rax,(%rsp)
  400b46:	xor    %eax,%eax
  400b48:	callq  400750 <syscall@plt>
  400b4d:	mov    %rsp,%rdx
  400b50:	mov    $0x80,%esi
  400b55:	mov    %eax,%edi
  400b57:	callq  400740 <sched_setaffinity@plt>
  400b5c:	test   %eax,%eax
  400b5e:	jne    400cd1 <thread+0x1c1>
  400b64:	mov    $0xf4240,%esi
  400b69:	mov    $0x1,%edi
  400b6e:	mov    $0xfffffff0,%r9d
  400b74:	mov    $0x100,%r8d
  400b7a:	nopw   0x0(%rax,%rax,1)
  400b80:	mov    %edi,%eax
  400b82:	lock xadd %eax,0x2014fe(%rip)        # 602088 <lock+0x8>
  400b8a:	mov    0x2014fc(%rip),%edx        # 60208c <lock+0xc>
  400b90:	cmp    %eax,%edx
  400b92:	je     400ba4 <thread+0x94>
  400b94:	nopl   0x0(%rax)
  400b98:	pause  
  400b9a:	mov    0x2014ec(%rip),%edx        # 60208c <lock+0xc>
  400ba0:	cmp    %edx,%eax
  400ba2:	jne    400b98 <thread+0x88>
  400ba4:	and    $0x1,%eax
  400ba7:	or     $0x2,%eax
  400baa:	lock xadd %eax,0x2014ce(%rip)        # 602080 <lock>
  400bb2:	mov    0x2014cc(%rip),%edx        # 602084 <lock+0x4>
  400bb8:	cmp    %edx,%eax
  400bba:	je     400bcc <thread+0xbc>
  400bbc:	nopl   0x0(%rax)
  400bc0:	pause  
  400bc2:	mov    0x2014bc(%rip),%edx        # 602084 <lock+0x4>
  400bc8:	cmp    %edx,%eax
  400bca:	jne    400bc0 <thread+0xb0>
  400bcc:	mov    0x2014c2(%rip),%edx        # 602094 <locked>
  400bd2:	test   %edx,%edx
  400bd4:	jne    400ce7 <thread+0x1d7>
  400bda:	lock incl 0x2014b3(%rip)        # 602094 <locked>
  400be1:	lock incl 0x2014ac(%rip)        # 602094 <locked>
  400be8:	lock incl 0x2014a5(%rip)        # 602094 <locked>
  400bef:	lock incl 0x20149e(%rip)        # 602094 <locked>
  400bf6:	lock incl 0x201497(%rip)        # 602094 <locked>
  400bfd:	lock incl 0x201490(%rip)        # 602094 <locked>
  400c04:	lock incl 0x201489(%rip)        # 602094 <locked>
  400c0b:	lock incl 0x201482(%rip)        # 602094 <locked>
  400c12:	mov    0x20147c(%rip),%edx        # 602094 <locked>
  400c18:	cmp    $0x8,%edx
  400c1b:	jne    400cfa <thread+0x1ea>
  400c21:	lock decl 0x20146c(%rip)        # 602094 <locked>
  400c28:	lock decl 0x201465(%rip)        # 602094 <locked>
  400c2f:	lock decl 0x20145e(%rip)        # 602094 <locked>
  400c36:	lock decl 0x201457(%rip)        # 602094 <locked>
  400c3d:	lock decl 0x201450(%rip)        # 602094 <locked>
  400c44:	lock decl 0x201449(%rip)        # 602094 <locked>
  400c4b:	lock decl 0x201442(%rip)        # 602094 <locked>
  400c52:	lock decl 0x20143b(%rip)        # 602094 <locked>
  400c59:	mov    0x201435(%rip),%edx        # 602094 <locked>
  400c5f:	test   %edx,%edx
  400c61:	jne    400d0d <thread+0x1fd>
  400c67:	lea    0x201412(%rip),%rcx        # 602080 <lock>
  400c6e:	lock and %r9d,0x20140a(%rip)        # 602080 <lock>
  400c76:	mov    %edi,%eax
  400c78:	lock xadd %eax,0x20140c(%rip)        # 60208c <lock+0xc>
  400c80:	mov    %r8d,%edx
  400c83:	lock xadd %edx,0x2013f5(%rip)        # 602080 <lock>
  400c8b:	and    $0x3,%edx
  400c8e:	je     400cab <thread+0x19b>
  400c90:	mov    0x2013ea(%rip),%eax        # 602080 <lock>
  400c96:	and    $0x3,%eax
  400c99:	cmp    %eax,%edx
  400c9b:	jne    400cab <thread+0x19b>
  400c9d:	nopl   (%rax)
  400ca0:	pause  
  400ca2:	mov    (%rcx),%eax
  400ca4:	and    $0x3,%eax
  400ca7:	cmp    %eax,%edx
  400ca9:	je     400ca0 <thread+0x190>
  400cab:	mov    0x2013e3(%rip),%edx        # 602094 <locked>
  400cb1:	test   %edx,%edx
  400cb3:	jne    400d20 <thread+0x210>
  400cb5:	mov    %r8d,%eax
  400cb8:	lock xadd %eax,0x2013c4(%rip)        # 602084 <lock+0x4>
  400cc0:	sub    $0x1,%esi
  400cc3:	jne    400b80 <thread+0x70>
  400cc9:	sub    $0xffffffffffffff80,%rsp
  400ccd:	xor    %eax,%eax
  400ccf:	pop    %rbx
  400cd0:	retq   
  400cd1:	lea    0xf8(%rip),%rdi        # 400dd0 <__dso_handle+0x8>
  400cd8:	callq  400780 <perror@plt>
  400cdd:	mov    $0x1,%edi
  400ce2:	callq  4007b0 <exit@plt>
  400ce7:	lea    0x22a(%rip),%rdi        # 400f18 <__dso_handle+0x150>
  400cee:	mov    $0x44,%esi
  400cf3:	xor    %eax,%eax
  400cf5:	callq  400a60 <ck_error>
  400cfa:	lea    0x22f(%rip),%rdi        # 400f30 <__dso_handle+0x168>
  400d01:	mov    $0x52,%esi
  400d06:	xor    %eax,%eax
  400d08:	callq  400a60 <ck_error>
  400d0d:	lea    0x204(%rip),%rdi        # 400f18 <__dso_handle+0x150>
  400d14:	mov    $0x60,%esi
  400d19:	xor    %eax,%eax
  400d1b:	callq  400a60 <ck_error>
  400d20:	lea    0x221(%rip),%rdi        # 400f48 <__dso_handle+0x180>
  400d27:	mov    $0x69,%esi
  400d2c:	xor    %eax,%eax
  400d2e:	callq  400a60 <ck_error>
  400d33:	nopw   %cs:0x0(%rax,%rax,1)
  400d3d:	nopl   (%rax)

0000000000400d40 <__libc_csu_init>:
  400d40:	push   %r15
  400d42:	push   %r14
  400d44:	mov    %edi,%r15d
  400d47:	push   %r13
  400d49:	push   %r12
  400d4b:	lea    0x20109e(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400d52:	push   %rbp
  400d53:	lea    0x20109e(%rip),%rbp        # 601df8 <__init_array_end>
  400d5a:	push   %rbx
  400d5b:	mov    %rsi,%r14
  400d5e:	mov    %rdx,%r13
  400d61:	sub    %r12,%rbp
  400d64:	sub    $0x8,%rsp
  400d68:	sar    $0x3,%rbp
  400d6c:	callq  400700 <_init>
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
