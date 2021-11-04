// TC_OUT
00000000004009f8 <parse_option>:
  4009f8:	push   %rbp
  4009f9:	mov    %rsp,%rbp
  4009fc:	sub    $0x30,%rsp
  400a00:	mov    %edi,-0x14(%rbp)
  400a03:	mov    %rsi,-0x20(%rbp)
  400a07:	mov    %rdx,-0x28(%rbp)
  400a0b:	mov    -0x28(%rbp),%rax
  400a0f:	mov    $0x10,%edx
  400a14:	mov    $0x0,%esi
  400a19:	mov    %rax,%rdi
  400a1c:	callq  400810 <memset@plt>
  400a21:	mov    -0x28(%rbp),%rax
  400a25:	movl   $0x7a120,(%rax)
  400a2b:	mov    -0x28(%rbp),%rax
  400a2f:	movl   $0x4,0x4(%rax)
  400a36:	movq   $0x400986,0x20172f(%rip)        # 602170 <spin_func>
  400a41:	movq   $0x4009c7,0x20172c(%rip)        # 602178 <work_func>
  400a4c:	movl   $0x0,-0x4(%rbp)
  400a53:	lea    -0xc(%rbp),%rdx
  400a57:	mov    -0x20(%rbp),%rsi
  400a5b:	mov    -0x14(%rbp),%eax
  400a5e:	mov    %rdx,%r8
  400a61:	mov    $0x6020a0,%ecx
  400a66:	mov    $0x400dd0,%edx
  400a6b:	mov    %eax,%edi
  400a6d:	callq  4007f0 <getopt_long@plt>
  400a72:	mov    %eax,-0x8(%rbp)
  400a75:	cmpl   $0xffffffff,-0x8(%rbp)
  400a79:	je     400b24 <parse_option+0x12c>
  400a7f:	mov    -0x8(%rbp),%eax
  400a82:	cmp    $0x6e,%eax
  400a85:	je     400ab6 <parse_option+0xbe>
  400a87:	cmp    $0x6e,%eax
  400a8a:	jg     400a93 <parse_option+0x9b>
  400a8c:	cmp    $0x63,%eax
  400a8f:	je     400af0 <parse_option+0xf8>
  400a91:	jmp    400b10 <parse_option+0x118>
  400a93:	cmp    $0x73,%eax
  400a96:	je     400ad0 <parse_option+0xd8>
  400a98:	cmp    $0x74,%eax
  400a9b:	jne    400b10 <parse_option+0x118>
  400a9d:	mov    0x2016a4(%rip),%rax        # 602148 <optarg@@GLIBC_2.2.5>
  400aa4:	mov    %rax,%rdi
  400aa7:	callq  400850 <atoi@plt>
  400aac:	mov    %eax,%edx
  400aae:	mov    -0x28(%rbp),%rax
  400ab2:	mov    %edx,(%rax)
  400ab4:	jmp    400b1b <parse_option+0x123>
  400ab6:	mov    0x20168b(%rip),%rax        # 602148 <optarg@@GLIBC_2.2.5>
  400abd:	mov    %rax,%rdi
  400ac0:	callq  400850 <atoi@plt>
  400ac5:	mov    %eax,%edx
  400ac7:	mov    -0x28(%rbp),%rax
  400acb:	mov    %edx,0x4(%rax)
  400ace:	jmp    400b1b <parse_option+0x123>
  400ad0:	mov    0x201671(%rip),%rax        # 602148 <optarg@@GLIBC_2.2.5>
  400ad7:	mov    %rax,%rdi
  400ada:	callq  400850 <atoi@plt>
  400adf:	test   %eax,%eax
  400ae1:	je     400b17 <parse_option+0x11f>
  400ae3:	movq   $0x4009a1,0x201682(%rip)        # 602170 <spin_func>
  400aee:	jmp    400b17 <parse_option+0x11f>
  400af0:	mov    0x201651(%rip),%rax        # 602148 <optarg@@GLIBC_2.2.5>
  400af7:	mov    %rax,%rdi
  400afa:	callq  400850 <atoi@plt>
  400aff:	test   %eax,%eax
  400b01:	je     400b1a <parse_option+0x122>
  400b03:	movq   $0x4009db,0x20166a(%rip)        # 602178 <work_func>
  400b0e:	jmp    400b1a <parse_option+0x122>
  400b10:	mov    $0xffffffea,%eax
  400b15:	jmp    400b28 <parse_option+0x130>
  400b17:	nop
  400b18:	jmp    400b1b <parse_option+0x123>
  400b1a:	nop
  400b1b:	addl   $0x1,-0x4(%rbp)
  400b1f:	jmpq   400a53 <parse_option+0x5b>
  400b24:	nop
  400b25:	mov    -0x4(%rbp),%eax
  400b28:	leaveq 
  400b29:	retq   
