// TC_OUT thread,0x400d20,0x400d29,0x0(%rcx)
// TC_OUT thread,0x400dd0,0x400dd6,0x0(%rcx)
// TC_OUT thread_latch,0x400b68,0x400b8b,0x0(%rcx),0x0(0x60208c)
// TC_OUT thread_latch,0x400b90,0x400b96,0x0(%rcx)
validate:     file format elf64-x86-64


Disassembly of section .init:

0000000000400770 <_init>:
  400770:	sub    $0x8,%rsp
  400774:	mov    0x201875(%rip),%rax        # 601ff0 <_DYNAMIC+0x1e8>
  40077b:	test   %rax,%rax
  40077e:	je     400782 <_init+0x12>
  400780:	callq  *%rax
  400782:	add    $0x8,%rsp
  400786:	retq   

Disassembly of section .plt:

0000000000400790 <pthread_create@plt-0x10>:
  400790:	pushq  0x201872(%rip)        # 602008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400796:	jmpq   *0x201874(%rip)        # 602010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40079c:	nopl   0x0(%rax)

00000000004007a0 <pthread_create@plt>:
  4007a0:	jmpq   *0x201872(%rip)        # 602018 <_GLOBAL_OFFSET_TABLE_+0x18>
  4007a6:	pushq  $0x0
  4007ab:	jmpq   400790 <_init+0x20>

00000000004007b0 <sched_setaffinity@plt>:
  4007b0:	jmpq   *0x20186a(%rip)        # 602020 <_GLOBAL_OFFSET_TABLE_+0x20>
  4007b6:	pushq  $0x1
  4007bb:	jmpq   400790 <_init+0x20>

00000000004007c0 <fputc@plt>:
  4007c0:	jmpq   *0x201862(%rip)        # 602028 <_GLOBAL_OFFSET_TABLE_+0x28>
  4007c6:	pushq  $0x2
  4007cb:	jmpq   400790 <_init+0x20>

00000000004007d0 <fprintf@plt>:
  4007d0:	jmpq   *0x20185a(%rip)        # 602030 <_GLOBAL_OFFSET_TABLE_+0x30>
  4007d6:	pushq  $0x3
  4007db:	jmpq   400790 <_init+0x20>

00000000004007e0 <syscall@plt>:
  4007e0:	jmpq   *0x201852(%rip)        # 602038 <_GLOBAL_OFFSET_TABLE_+0x38>
  4007e6:	pushq  $0x4
  4007eb:	jmpq   400790 <_init+0x20>

00000000004007f0 <strtol@plt>:
  4007f0:	jmpq   *0x20184a(%rip)        # 602040 <_GLOBAL_OFFSET_TABLE_+0x40>
  4007f6:	pushq  $0x5
  4007fb:	jmpq   400790 <_init+0x20>

0000000000400800 <malloc@plt>:
  400800:	jmpq   *0x201842(%rip)        # 602048 <_GLOBAL_OFFSET_TABLE_+0x48>
  400806:	pushq  $0x6
  40080b:	jmpq   400790 <_init+0x20>

0000000000400810 <perror@plt>:
  400810:	jmpq   *0x20183a(%rip)        # 602050 <_GLOBAL_OFFSET_TABLE_+0x50>
  400816:	pushq  $0x7
  40081b:	jmpq   400790 <_init+0x20>

0000000000400820 <pthread_join@plt>:
  400820:	jmpq   *0x201832(%rip)        # 602058 <_GLOBAL_OFFSET_TABLE_+0x58>
  400826:	pushq  $0x8
  40082b:	jmpq   400790 <_init+0x20>

0000000000400830 <vfprintf@plt>:
  400830:	jmpq   *0x20182a(%rip)        # 602060 <_GLOBAL_OFFSET_TABLE_+0x60>
  400836:	pushq  $0x9
  40083b:	jmpq   400790 <_init+0x20>

0000000000400840 <exit@plt>:
  400840:	jmpq   *0x201822(%rip)        # 602068 <_GLOBAL_OFFSET_TABLE_+0x68>
  400846:	pushq  $0xa
  40084b:	jmpq   400790 <_init+0x20>

0000000000400850 <fwrite@plt>:
  400850:	jmpq   *0x20181a(%rip)        # 602070 <_GLOBAL_OFFSET_TABLE_+0x70>
  400856:	pushq  $0xb
  40085b:	jmpq   400790 <_init+0x20>

Disassembly of section .text:

0000000000400860 <main>:
  400860:	push   %rbp
  400861:	push   %rbx
  400862:	sub    $0x8,%rsp
  400866:	cmp    $0x3,%edi
  400869:	jne    4008ea <main+0x8a>
  40086b:	mov    0x8(%rsi),%rdi
  40086f:	mov    %rsi,%rbp
  400872:	mov    $0xa,%edx
  400877:	xor    %esi,%esi
  400879:	callq  4007f0 <strtol@plt>
  40087e:	test   %eax,%eax
  400880:	mov    %eax,0x20180a(%rip)        # 602090 <nthr>
  400886:	jle    400906 <main+0xa6>
  400888:	cltq   
  40088a:	lea    0x0(,%rax,8),%rdi
  400892:	callq  400800 <malloc@plt>
  400897:	test   %rax,%rax
  40089a:	mov    %rax,%rbx
  40089d:	je     4008f8 <main+0x98>
  40089f:	mov    0x10(%rbp),%rdi
  4008a3:	mov    $0xa,%edx
  4008a8:	xor    %esi,%esi
  4008aa:	callq  4007f0 <strtol@plt>
  4008af:	lea    0x8d2(%rip),%rdx        # 401188 <__dso_handle+0x160>
  4008b6:	lea    0x423(%rip),%rsi        # 400ce0 <thread>
  4008bd:	mov    %rbx,%rdi
  4008c0:	mov    %eax,0x2017d2(%rip)        # 602098 <a>
  4008c6:	callq  400e80 <swlock_test>
  4008cb:	lea    0x8be(%rip),%rdx        # 401190 <__dso_handle+0x168>
  4008d2:	lea    0x257(%rip),%rsi        # 400b30 <thread_latch>
  4008d9:	mov    %rbx,%rdi
  4008dc:	callq  400e80 <swlock_test>
  4008e1:	add    $0x8,%rsp
  4008e5:	xor    %eax,%eax
  4008e7:	pop    %rbx
  4008e8:	pop    %rbp
  4008e9:	retq   
  4008ea:	lea    0x787(%rip),%rdi        # 401078 <__dso_handle+0x50>
  4008f1:	xor    %eax,%eax
  4008f3:	callq  400a80 <ck_error>
  4008f8:	lea    0x7e9(%rip),%rdi        # 4010e8 <__dso_handle+0xc0>
  4008ff:	xor    %eax,%eax
  400901:	callq  400a80 <ck_error>
  400906:	lea    0x7a3(%rip),%rdi        # 4010b0 <__dso_handle+0x88>
  40090d:	xor    %eax,%eax
  40090f:	callq  400a80 <ck_error>
  400914:	nopw   %cs:0x0(%rax,%rax,1)
  40091e:	xchg   %ax,%ax

0000000000400920 <_start>:
  400920:	xor    %ebp,%ebp
  400922:	mov    %rdx,%r9
  400925:	pop    %rsi
  400926:	mov    %rsp,%rdx
  400929:	and    $0xfffffffffffffff0,%rsp
  40092d:	push   %rax
  40092e:	push   %rsp
  40092f:	mov    $0x401010,%r8
  400936:	mov    $0x400fa0,%rcx
  40093d:	mov    $0x400860,%rdi
  400944:	callq  *0x20169e(%rip)        # 601fe8 <_DYNAMIC+0x1e0>
  40094a:	hlt    
  40094b:	nopl   0x0(%rax,%rax,1)

0000000000400950 <deregister_tm_clones>:
  400950:	mov    $0x602087,%eax
  400955:	push   %rbp
  400956:	sub    $0x602080,%rax
  40095c:	cmp    $0xe,%rax
  400960:	mov    %rsp,%rbp
  400963:	jbe    400980 <deregister_tm_clones+0x30>
  400965:	mov    $0x0,%eax
  40096a:	test   %rax,%rax
  40096d:	je     400980 <deregister_tm_clones+0x30>
  40096f:	pop    %rbp
  400970:	mov    $0x602080,%edi
  400975:	jmpq   *%rax
  400977:	nopw   0x0(%rax,%rax,1)
  400980:	pop    %rbp
  400981:	retq   
  400982:	nopl   0x0(%rax)
  400986:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400990 <register_tm_clones>:
  400990:	mov    $0x602080,%esi
  400995:	push   %rbp
  400996:	sub    $0x602080,%rsi
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
  4009be:	mov    $0x602080,%edi
  4009c3:	jmpq   *%rax
  4009c5:	nopl   (%rax)
  4009c8:	pop    %rbp
  4009c9:	retq   
  4009ca:	nopw   0x0(%rax,%rax,1)

00000000004009d0 <__do_global_dtors_aux>:
  4009d0:	cmpb   $0x0,0x2016a9(%rip)        # 602080 <__TMC_END__>
  4009d7:	jne    4009ea <__do_global_dtors_aux+0x1a>
  4009d9:	push   %rbp
  4009da:	mov    %rsp,%rbp
  4009dd:	callq  400950 <deregister_tm_clones>
  4009e2:	pop    %rbp
  4009e3:	movb   $0x1,0x201696(%rip)        # 602080 <__TMC_END__>
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

0000000000400a20 <aff_iterate.constprop.0>:
  400a20:	push   %rbx
  400a21:	add    $0xffffffffffffff80,%rsp
  400a25:	mov    0x20166d(%rip),%esi        # 602098 <a>
  400a2b:	lock xadd %esi,0x201669(%rip)        # 60209c <a+0x4>
  400a33:	xor    %eax,%eax
  400a35:	mov    %rsp,%rdi
  400a38:	mov    $0x10,%ecx
  400a3d:	rep stos %rax,%es:(%rdi)
  400a40:	mov    %esi,%ecx
  400a42:	mov    $0x1,%eax
  400a47:	mov    $0xba,%edi
  400a4c:	and    $0x3,%ecx
  400a4f:	shl    %cl,%rax
  400a52:	mov    %rax,(%rsp)
  400a56:	xor    %eax,%eax
  400a58:	callq  4007e0 <syscall@plt>
  400a5d:	mov    %rsp,%rdx
  400a60:	mov    $0x80,%esi
  400a65:	mov    %eax,%edi
  400a67:	callq  4007b0 <sched_setaffinity@plt>
  400a6c:	sub    $0xffffffffffffff80,%rsp
  400a70:	pop    %rbx
  400a71:	retq   
  400a72:	nopl   0x0(%rax)
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
  400b0a:	mov    0x2014e7(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400b11:	mov    (%rax),%rdi
  400b14:	callq  400830 <vfprintf@plt>
  400b19:	mov    $0x1,%edi
  400b1e:	callq  400840 <exit@plt>
  400b23:	nopl   (%rax)
  400b26:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400b30 <thread_latch>:
  400b30:	push   %rbx
  400b31:	mov    (%rdi),%ebx
  400b33:	callq  400a20 <aff_iterate.constprop.0>
  400b38:	test   %eax,%eax
  400b3a:	jne    400c7e <thread_latch+0x14e>
  400b40:	lea    0x201545(%rip),%rcx        # 60208c <lock>
  400b47:	mov    $0xf4240,%r9d
  400b4d:	mov    $0x80000000,%edi
  400b52:	mov    $0xc0000000,%r8d
  400b58:	mov    $0x1,%esi
  400b5d:	test   %ebx,%ebx
  400b5f:	jne    400b92 <thread_latch+0x62>
  400b61:	lock or %edi,(%rcx)
  400b64:	nopl   0x0(%rax)
  400b68:	mov    %edi,%eax
  400b6a:	lock cmpxchg %r8d,0x201519(%rip)        # 60208c <lock>
  400b73:	sete   %al
  400b76:	test   %al,%al
  400b78:	jne    400bd0 <thread_latch+0xa0>
  400b7a:	nopw   0x0(%rax,%rax,1)
  400b80:	pause  
  400b82:	mov    (%rcx),%eax
  400b84:	cmp    $0x80000000,%eax
  400b89:	jne    400b80 <thread_latch+0x50>
  400b8b:	jmp    400b68 <thread_latch+0x38>
  400b8d:	nopl   (%rax)
  400b90:	pause  
  400b92:	mov    (%rcx),%eax
  400b94:	test   %eax,%eax
  400b96:	js     400b90 <thread_latch+0x60>
  400b98:	mov    %esi,%eax
  400b9a:	lock xadd %eax,0x2014ea(%rip)        # 60208c <lock>
  400ba2:	and    $0xc0000000,%eax
  400ba7:	je     400bb5 <thread_latch+0x85>
  400ba9:	cmp    $0x80000000,%eax
  400bae:	jne    400b92 <thread_latch+0x62>
  400bb0:	lock decl (%rcx)
  400bb3:	jmp    400b92 <thread_latch+0x62>
  400bb5:	mov    0x2014d9(%rip),%edx        # 602094 <locked>
  400bbb:	test   %edx,%edx
  400bbd:	jne    400ccd <thread_latch+0x19d>
  400bc3:	lock decl (%rcx)
  400bc6:	sub    $0x1,%r9d
  400bca:	jne    400b5d <thread_latch+0x2d>
  400bcc:	xor    %eax,%eax
  400bce:	pop    %rbx
  400bcf:	retq   
  400bd0:	mov    (%rcx),%eax
  400bd2:	mov    %eax,0x2014b0(%rip)        # 602088 <copy>
  400bd8:	mov    0x2014b6(%rip),%edx        # 602094 <locked>
  400bde:	test   %edx,%edx
  400be0:	jne    400cba <thread_latch+0x18a>
  400be6:	lock incl 0x2014a7(%rip)        # 602094 <locked>
  400bed:	lock incl 0x2014a0(%rip)        # 602094 <locked>
  400bf4:	lock incl 0x201499(%rip)        # 602094 <locked>
  400bfb:	lock incl 0x201492(%rip)        # 602094 <locked>
  400c02:	lock incl 0x20148b(%rip)        # 602094 <locked>
  400c09:	lock incl 0x201484(%rip)        # 602094 <locked>
  400c10:	lock incl 0x20147d(%rip)        # 602094 <locked>
  400c17:	lock incl 0x201476(%rip)        # 602094 <locked>
  400c1e:	mov    0x201470(%rip),%edx        # 602094 <locked>
  400c24:	cmp    $0x8,%edx
  400c27:	jne    400ca7 <thread_latch+0x177>
  400c29:	lock decl 0x201464(%rip)        # 602094 <locked>
  400c30:	lock decl 0x20145d(%rip)        # 602094 <locked>
  400c37:	lock decl 0x201456(%rip)        # 602094 <locked>
  400c3e:	lock decl 0x20144f(%rip)        # 602094 <locked>
  400c45:	lock decl 0x201448(%rip)        # 602094 <locked>
  400c4c:	lock decl 0x201441(%rip)        # 602094 <locked>
  400c53:	lock decl 0x20143a(%rip)        # 602094 <locked>
  400c5a:	lock decl 0x201433(%rip)        # 602094 <locked>
  400c61:	mov    0x20142d(%rip),%edx        # 602094 <locked>
  400c67:	test   %edx,%edx
  400c69:	jne    400c94 <thread_latch+0x164>
  400c6b:	mov    0x201417(%rip),%eax        # 602088 <copy>
  400c71:	mov    %eax,(%rcx)
  400c73:	movl   $0x0,(%rcx)
  400c79:	jmpq   400b92 <thread_latch+0x62>
  400c7e:	lea    0x3ab(%rip),%rdi        # 401030 <__dso_handle+0x8>
  400c85:	callq  400810 <perror@plt>
  400c8a:	mov    $0x1,%edi
  400c8f:	callq  400840 <exit@plt>
  400c94:	lea    0x47d(%rip),%rdi        # 401118 <__dso_handle+0xf0>
  400c9b:	mov    $0x13f,%esi
  400ca0:	xor    %eax,%eax
  400ca2:	callq  400a80 <ck_error>
  400ca7:	lea    0x482(%rip),%rdi        # 401130 <__dso_handle+0x108>
  400cae:	mov    $0x131,%esi
  400cb3:	xor    %eax,%eax
  400cb5:	callq  400a80 <ck_error>
  400cba:	lea    0x457(%rip),%rdi        # 401118 <__dso_handle+0xf0>
  400cc1:	mov    $0x123,%esi
  400cc6:	xor    %eax,%eax
  400cc8:	callq  400a80 <ck_error>
  400ccd:	lea    0x474(%rip),%rdi        # 401148 <__dso_handle+0x120>
  400cd4:	mov    $0x14a,%esi
  400cd9:	xor    %eax,%eax
  400cdb:	callq  400a80 <ck_error>

0000000000400ce0 <thread>:
  400ce0:	push   %rbx
  400ce1:	mov    (%rdi),%ebx
  400ce3:	callq  400a20 <aff_iterate.constprop.0>
  400ce8:	test   %eax,%eax
  400cea:	jne    400e0f <thread+0x12f>
  400cf0:	lea    0x201395(%rip),%rcx        # 60208c <lock>
  400cf7:	mov    $0xf4240,%edi
  400cfc:	mov    $0x80000000,%r8d
  400d02:	mov    $0x1,%esi
  400d07:	test   %ebx,%ebx
  400d09:	jne    400dd2 <thread+0xf2>
  400d0f:	lock or %r8d,(%rcx)
  400d13:	mov    (%rcx),%eax
  400d15:	test   $0x3fffffff,%eax
  400d1a:	je     400d2b <thread+0x4b>
  400d1c:	nopl   0x0(%rax)
  400d20:	pause  
  400d22:	mov    (%rcx),%eax
  400d24:	test   $0x3fffffff,%eax
  400d29:	jne    400d20 <thread+0x40>
  400d2b:	mov    0x201363(%rip),%edx        # 602094 <locked>
  400d31:	test   %edx,%edx
  400d33:	jne    400e4b <thread+0x16b>
  400d39:	lock incl 0x201354(%rip)        # 602094 <locked>
  400d40:	lock incl 0x20134d(%rip)        # 602094 <locked>
  400d47:	lock incl 0x201346(%rip)        # 602094 <locked>
  400d4e:	lock incl 0x20133f(%rip)        # 602094 <locked>
  400d55:	lock incl 0x201338(%rip)        # 602094 <locked>
  400d5c:	lock incl 0x201331(%rip)        # 602094 <locked>
  400d63:	lock incl 0x20132a(%rip)        # 602094 <locked>
  400d6a:	lock incl 0x201323(%rip)        # 602094 <locked>
  400d71:	mov    0x20131d(%rip),%edx        # 602094 <locked>
  400d77:	cmp    $0x8,%edx
  400d7a:	jne    400e38 <thread+0x158>
  400d80:	lock decl 0x20130d(%rip)        # 602094 <locked>
  400d87:	lock decl 0x201306(%rip)        # 602094 <locked>
  400d8e:	lock decl 0x2012ff(%rip)        # 602094 <locked>
  400d95:	lock decl 0x2012f8(%rip)        # 602094 <locked>
  400d9c:	lock decl 0x2012f1(%rip)        # 602094 <locked>
  400da3:	lock decl 0x2012ea(%rip)        # 602094 <locked>
  400daa:	lock decl 0x2012e3(%rip)        # 602094 <locked>
  400db1:	lock decl 0x2012dc(%rip)        # 602094 <locked>
  400db8:	mov    0x2012d6(%rip),%edx        # 602094 <locked>
  400dbe:	test   %edx,%edx
  400dc0:	jne    400e25 <thread+0x145>
  400dc2:	lock andl $0x3fffffff,(%rcx)
  400dc9:	jmp    400dd2 <thread+0xf2>
  400dcb:	nopl   0x0(%rax,%rax,1)
  400dd0:	pause  
  400dd2:	mov    (%rcx),%eax
  400dd4:	test   %eax,%eax
  400dd6:	js     400dd0 <thread+0xf0>
  400dd8:	mov    %esi,%eax
  400dda:	lock xadd %eax,0x2012aa(%rip)        # 60208c <lock>
  400de2:	and    $0xc0000000,%eax
  400de7:	je     400df5 <thread+0x115>
  400de9:	cmp    $0x80000000,%eax
  400dee:	jne    400dd2 <thread+0xf2>
  400df0:	lock decl (%rcx)
  400df3:	jmp    400dd2 <thread+0xf2>
  400df5:	mov    0x201299(%rip),%edx        # 602094 <locked>
  400dfb:	test   %edx,%edx
  400dfd:	jne    400e5e <thread+0x17e>
  400dff:	lock decl (%rcx)
  400e02:	sub    $0x1,%edi
  400e05:	jne    400d07 <thread+0x27>
  400e0b:	xor    %eax,%eax
  400e0d:	pop    %rbx
  400e0e:	retq   
  400e0f:	lea    0x21a(%rip),%rdi        # 401030 <__dso_handle+0x8>
  400e16:	callq  400810 <perror@plt>
  400e1b:	mov    $0x1,%edi
  400e20:	callq  400840 <exit@plt>
  400e25:	lea    0x2ec(%rip),%rdi        # 401118 <__dso_handle+0xf0>
  400e2c:	mov    $0x182,%esi
  400e31:	xor    %eax,%eax
  400e33:	callq  400a80 <ck_error>
  400e38:	lea    0x2f1(%rip),%rdi        # 401130 <__dso_handle+0x108>
  400e3f:	mov    $0x174,%esi
  400e44:	xor    %eax,%eax
  400e46:	callq  400a80 <ck_error>
  400e4b:	lea    0x2c6(%rip),%rdi        # 401118 <__dso_handle+0xf0>
  400e52:	mov    $0x166,%esi
  400e57:	xor    %eax,%eax
  400e59:	callq  400a80 <ck_error>
  400e5e:	lea    0x2e3(%rip),%rdi        # 401148 <__dso_handle+0x120>
  400e65:	mov    $0x18c,%esi
  400e6a:	xor    %eax,%eax
  400e6c:	callq  400a80 <ck_error>
  400e71:	nopl   0x0(%rax,%rax,1)
  400e76:	nopw   %cs:0x0(%rax,%rax,1)

0000000000400e80 <swlock_test>:
  400e80:	push   %rbp
  400e81:	mov    %rsp,%rbp
  400e84:	push   %r15
  400e86:	push   %r14
  400e88:	push   %r13
  400e8a:	push   %r12
  400e8c:	mov    %rdi,%r13
  400e8f:	push   %rbx
  400e90:	mov    %rsi,%r12
  400e93:	lea    0x2c6(%rip),%rsi        # 401160 <__dso_handle+0x138>
  400e9a:	xor    %r15d,%r15d
  400e9d:	mov    %r13,%r14
  400ea0:	sub    $0x8,%rsp
  400ea4:	movslq 0x2011e5(%rip),%rax        # 602090 <nthr>
  400eab:	lea    0x12(,%rax,4),%rax
  400eb3:	and    $0xfffffffffffffff0,%rax
  400eb7:	sub    %rax,%rsp
  400eba:	mov    0x201137(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400ec1:	mov    %rsp,%rbx
  400ec4:	mov    (%rax),%rdi
  400ec7:	xor    %eax,%eax
  400ec9:	callq  4007d0 <fprintf@plt>
  400ece:	mov    0x2011bc(%rip),%edx        # 602090 <nthr>
  400ed4:	test   %edx,%edx
  400ed6:	jle    400f10 <swlock_test+0x90>
  400ed8:	nopl   0x0(%rax,%rax,1)
  400ee0:	mov    %r15d,(%rbx)
  400ee3:	xor    %esi,%esi
  400ee5:	mov    %rbx,%rcx
  400ee8:	mov    %r12,%rdx
  400eeb:	mov    %r14,%rdi
  400eee:	callq  4007a0 <pthread_create@plt>
  400ef3:	test   %eax,%eax
  400ef5:	jne    400f81 <swlock_test+0x101>
  400efb:	add    $0x1,%r15d
  400eff:	add    $0x4,%rbx
  400f03:	add    $0x8,%r14
  400f07:	cmp    %r15d,0x201182(%rip)        # 602090 <nthr>
  400f0e:	jg     400ee0 <swlock_test+0x60>
  400f10:	mov    0x2010e1(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400f17:	mov    $0x2e,%edi
  400f1c:	mov    $0x1,%ebx
  400f21:	mov    (%rax),%rsi
  400f24:	callq  4007c0 <fputc@plt>
  400f29:	mov    0x201161(%rip),%eax        # 602090 <nthr>
  400f2f:	test   %eax,%eax
  400f31:	jle    400f52 <swlock_test+0xd2>
  400f33:	nopl   0x0(%rax,%rax,1)
  400f38:	mov    -0x8(%r13,%rbx,8),%rdi
  400f3d:	xor    %esi,%esi
  400f3f:	callq  400820 <pthread_join@plt>
  400f44:	mov    %ebx,%eax
  400f46:	add    $0x1,%rbx
  400f4a:	cmp    %eax,0x201140(%rip)        # 602090 <nthr>
  400f50:	jg     400f38 <swlock_test+0xb8>
  400f52:	mov    0x20109f(%rip),%rax        # 601ff8 <_DYNAMIC+0x1f0>
  400f59:	lea    0x219(%rip),%rdi        # 401179 <__dso_handle+0x151>
  400f60:	mov    $0xe,%edx
  400f65:	mov    $0x1,%esi
  400f6a:	mov    (%rax),%rcx
  400f6d:	callq  400850 <fwrite@plt>
  400f72:	lea    -0x28(%rbp),%rsp
  400f76:	pop    %rbx
  400f77:	pop    %r12
  400f79:	pop    %r13
  400f7b:	pop    %r14
  400f7d:	pop    %r15
  400f7f:	pop    %rbp
  400f80:	retq   
  400f81:	lea    0xc8(%rip),%rdi        # 401050 <__dso_handle+0x28>
  400f88:	mov    %r15d,%esi
  400f8b:	xor    %eax,%eax
  400f8d:	callq  400a80 <ck_error>
  400f92:	nopw   %cs:0x0(%rax,%rax,1)
  400f9c:	nopl   0x0(%rax)

0000000000400fa0 <__libc_csu_init>:
  400fa0:	push   %r15
  400fa2:	push   %r14
  400fa4:	mov    %edi,%r15d
  400fa7:	push   %r13
  400fa9:	push   %r12
  400fab:	lea    0x200e3e(%rip),%r12        # 601df0 <__frame_dummy_init_array_entry>
  400fb2:	push   %rbp
  400fb3:	lea    0x200e3e(%rip),%rbp        # 601df8 <__init_array_end>
  400fba:	push   %rbx
  400fbb:	mov    %rsi,%r14
  400fbe:	mov    %rdx,%r13
  400fc1:	sub    %r12,%rbp
  400fc4:	sub    $0x8,%rsp
  400fc8:	sar    $0x3,%rbp
  400fcc:	callq  400770 <_init>
  400fd1:	test   %rbp,%rbp
  400fd4:	je     400ff6 <__libc_csu_init+0x56>
  400fd6:	xor    %ebx,%ebx
  400fd8:	nopl   0x0(%rax,%rax,1)
  400fe0:	mov    %r13,%rdx
  400fe3:	mov    %r14,%rsi
  400fe6:	mov    %r15d,%edi
  400fe9:	callq  *(%r12,%rbx,8)
  400fed:	add    $0x1,%rbx
  400ff1:	cmp    %rbx,%rbp
  400ff4:	jne    400fe0 <__libc_csu_init+0x40>
  400ff6:	add    $0x8,%rsp
  400ffa:	pop    %rbx
  400ffb:	pop    %rbp
  400ffc:	pop    %r12
  400ffe:	pop    %r13
  401000:	pop    %r14
  401002:	pop    %r15
  401004:	retq   
  401005:	nop
  401006:	nopw   %cs:0x0(%rax,%rax,1)

0000000000401010 <__libc_csu_fini>:
  401010:	repz retq 

Disassembly of section .fini:

0000000000401014 <_fini>:
  401014:	sub    $0x8,%rsp
  401018:	add    $0x8,%rsp
  40101c:	retq   
