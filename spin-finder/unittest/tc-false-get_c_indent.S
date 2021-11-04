// TC_OUT
00000000001167b0 <get_c_indent@@Base>:
  1167b0:	push   %r15
  1167b2:	push   %r14
  1167b4:	push   %r13
  1167b6:	push   %r12
  1167b8:	push   %rbp
  1167b9:	push   %rbx
  1167ba:	sub    $0x1a8,%rsp
  1167c1:	mov    %fs:0x28,%rax
  1167ca:	mov    %rax,0x198(%rsp)
  1167d2:	xor    %eax,%eax
  1167d4:	mov    0x397f35(%rip),%rax        # 4ae710 <curwin@@Base>
  1167db:	movl   $0x0,0xc0(%rsp)
  1167e6:	movq   $0x7fffffff,0xc8(%rsp)
  1167f2:	movl   $0x0,0xd0(%rsp)
  1167fd:	mov    0x38(%rax),%r13
  116801:	cmp    $0x1,%r13
  116805:	je     116aa0 <get_c_indent@@Base+0x2f0>
  11680b:	mov    0x397566(%rip),%rdx        # 4add78 <curbuf@@Base>
  116812:	mov    %r13,%rdi
  116815:	mov    0x1644(%rdx),%esi
  11681b:	mov    %esi,0x18(%rsp)
  11681f:	mov    0x40(%rax),%esi
  116822:	mov    0x44(%rax),%eax
  116825:	mov    %esi,0x14(%rsp)
  116829:	mov    %eax,0x38(%rsp)
  11682d:	callq  1007a0 <ml_get@@Base>
  116832:	mov    %rax,%rdi
  116835:	callq  11f220 <vim_strsave@@Base>
  11683a:	test   %rax,%rax
  11683d:	mov    %rax,%r14
  116840:	mov    %rax,0x8(%rsp)
  116845:	je     116aa0 <get_c_indent@@Base+0x2f0>
  11684b:	testb  $0x10,0x38a51a(%rip)        # 4a0d6c <State@@Base>
  116852:	je     116880 <get_c_indent@@Base+0xd0>
  116854:	mov    0x397eb5(%rip),%rax        # 4ae710 <curwin@@Base>
  11685b:	mov    %r14,%rdi
  11685e:	mov    0x40(%rax),%ebx
  116861:	callq  4ed80 <_init@@Base+0x190>
  116866:	cmp    %eax,%ebx
  116868:	jge    116880 <get_c_indent@@Base+0xd0>
  11686a:	movslq %ebx,%rax
  11686d:	add    %r14,%rax
  116870:	cmpb   $0x29,(%rax)
  116873:	je     11733d <get_c_indent@@Base+0xb8d>
  116879:	nopl   0x0(%rax)
  116880:	mov    0x8(%rsp),%rdi
  116885:	callq  607e0 <skipwhite@@Base>
  11688a:	mov    %rax,%r12
  11688d:	mov    0x397e7c(%rip),%rax        # 4ae710 <curwin@@Base>
  116894:	movl   $0x0,0x40(%rax)
  11689b:	callq  116570 <cin_islabel@@Base>
  1168a0:	mov    %eax,%r15d
  1168a3:	mov    0x3974ce(%rip),%rax        # 4add78 <curbuf@@Base>
  1168aa:	mov    0x1668(%rax),%edi
  1168b0:	callq  113fe0 <find_start_comment@@Base>
  1168b5:	test   %rax,%rax
  1168b8:	je     116acd <get_c_indent@@Base+0x31d>
  1168be:	mov    0x8(%rax),%rdx
  1168c2:	mov    (%rax),%rax
  1168c5:	mov    %rax,0xa0(%rsp)
  1168cd:	mov    0x3974a4(%rip),%rax        # 4add78 <curbuf@@Base>
  1168d4:	mov    %rdx,0xa8(%rsp)
  1168dc:	mov    0x1668(%rax),%edi
  1168e2:	callq  10e220 <smsg_attr@@Base+0x780>
  1168e7:	test   %rax,%rax
  1168ea:	je     116903 <get_c_indent@@Base+0x153>
  1168ec:	mov    0xa0(%rsp),%rsi
  1168f4:	cmp    %rsi,(%rax)
  1168f7:	je     116b17 <get_c_indent@@Base+0x367>
  1168fd:	jl     116aed <get_c_indent@@Base+0x33d>
  116903:	lea    0xa0(%rsp),%rax
  11690b:	mov    %rax,0x20(%rsp)
  116910:	cmpb   $0x23,(%r12)
  116915:	je     1170ec <get_c_indent@@Base+0x93c>
  11691b:	test   %r15d,%r15d
  11691e:	je     116940 <get_c_indent@@Base+0x190>
  116920:	mov    0x397451(%rip),%rax        # 4add78 <curbuf@@Base>
  116927:	mov    0x1678(%rax),%ebx
  11692d:	test   %ebx,%ebx
  11692f:	jne    116940 <get_c_indent@@Base+0x190>
  116931:	mov    0x161c(%rax),%eax
  116937:	test   %eax,%eax
  116939:	js     1173c9 <get_c_indent@@Base+0xc19>
  11693f:	nop
  116940:	cmpb   $0x2f,(%r12)
  116945:	je     116b36 <get_c_indent@@Base+0x386>
  11694b:	cmpq   $0x0,0x20(%rsp)
  116951:	je     116b50 <get_c_indent@@Base+0x3a0>
  116957:	lea    0x84(%rsp),%rax
  11695f:	mov    0x20(%rsp),%rsi
  116964:	mov    0x397da5(%rip),%rdi        # 4ae710 <curwin@@Base>
  11696b:	xor    %r8d,%r8d
  11696e:	xor    %ecx,%ecx
  116970:	lea    0xe0(%rsp),%rbx
  116978:	mov    %rax,%rdx
  11697b:	mov    %rax,0x60(%rsp)
  116980:	lea    0x160(%rsp),%r14
  116988:	callq  60170 <getvcol@@Base>
  11698d:	mov    0x84(%rsp),%eax
  116994:	mov    %r13,0x48(%rsp)
  116999:	mov    %r12,0x28(%rsp)
  11699e:	movb   $0x0,0xe0(%rsp)
  1169a6:	movb   $0x0,0x120(%rsp)
  1169ae:	movl   $0x0,0x50(%rsp)
  1169b6:	mov    %eax,(%rsp)
  1169b9:	mov    0x3973b8(%rip),%rax        # 4add78 <curbuf@@Base>
  1169c0:	movl   $0x0,0x40(%rsp)
  1169c8:	movl   $0x0,0x44(%rsp)
  1169d0:	movl   $0x1,0x18(%rsp)
  1169d8:	movl   $0x2,0x3c(%rsp)
  1169e0:	mov    0x13f8(%rax),%rdx
  1169e7:	lea    0xb0(%rsp),%rax
  1169ef:	mov    %rbx,0x30(%rsp)
  1169f4:	mov    %rax,%rsi
  1169f7:	lea    0x120(%rsp),%rax
  1169ff:	mov    %rdx,0xb0(%rsp)
  116a07:	mov    %rsi,%r13
  116a0a:	mov    %rax,0x58(%rsp)
  116a0f:	mov    %rax,%r12
  116a12:	nopw   0x0(%rax,%rax,1)
  116a18:	movzbl (%rdx),%eax
  116a1b:	test   %al,%al
  116a1d:	je     1174e3 <get_c_indent@@Base+0xd33>
  116a23:	xor    %r15d,%r15d
  116a26:	xor    %ebp,%ebp
  116a28:	xor    %ebx,%ebx
  116a2a:	jmp    116a6b <get_c_indent@@Base+0x2bb>
  116a2c:	nopl   0x0(%rax)
  116a30:	cmp    $0x73,%al
  116a32:	je     116a85 <get_c_indent@@Base+0x2d5>
  116a34:	cmp    $0x6c,%al
  116a36:	je     116d50 <get_c_indent@@Base+0x5a0>
  116a3c:	cmp    $0x72,%al
  116a3e:	je     116d50 <get_c_indent@@Base+0x5a0>
  116a44:	lea    -0x30(%rax),%ecx
  116a47:	cmp    $0x9,%cl
  116a4a:	jbe    116db8 <get_c_indent@@Base+0x608>
  116a50:	cmp    $0x2d,%al
  116a52:	je     116db8 <get_c_indent@@Base+0x608>
  116a58:	add    $0x1,%rdx
  116a5c:	mov    %rdx,0xb0(%rsp)
  116a64:	nopl   0x0(%rax)
  116a68:	movzbl (%rdx),%eax
  116a6b:	test   %al,%al
  116a6d:	je     116d70 <get_c_indent@@Base+0x5c0>
  116a73:	cmp    $0x3a,%al
  116a75:	je     116d70 <get_c_indent@@Base+0x5c0>
  116a7b:	mov    %eax,%ecx
  116a7d:	and    $0xfffffff7,%ecx
  116a80:	cmp    $0x65,%cl
  116a83:	jne    116a30 <get_c_indent@@Base+0x280>
  116a85:	lea    0x1(%rdx),%rcx
  116a89:	mov    %rcx,0xb0(%rsp)
  116a91:	movzbl (%rdx),%r15d
  116a95:	mov    %rcx,%rdx
  116a98:	jmp    116a68 <get_c_indent@@Base+0x2b8>
  116a9a:	nopw   0x0(%rax,%rax,1)
  116aa0:	xor    %ebx,%ebx
  116aa2:	mov    0x198(%rsp),%rsi
  116aaa:	xor    %fs:0x28,%rsi
  116ab3:	mov    %ebx,%eax
  116ab5:	jne    118125 <get_c_indent@@Base+0x1975>
  116abb:	add    $0x1a8,%rsp
  116ac2:	pop    %rbx
  116ac3:	pop    %rbp
  116ac4:	pop    %r12
  116ac6:	pop    %r13
  116ac8:	pop    %r14
  116aca:	pop    %r15
  116acc:	retq   
  116acd:	mov    0x3972a4(%rip),%rax        # 4add78 <curbuf@@Base>
  116ad4:	mov    0x1668(%rax),%edi
  116ada:	callq  10e220 <smsg_attr@@Base+0x780>
  116adf:	test   %rax,%rax
  116ae2:	mov    %rax,0x20(%rsp)
  116ae7:	je     116910 <get_c_indent@@Base+0x160>
  116aed:	mov    0x397c1c(%rip),%rdx        # 4ae710 <curwin@@Base>
  116af4:	mov    $0xffffffff,%ebx
  116af9:	mov    0x14(%rsp),%eax
  116afd:	mov    0x8(%rsp),%rdi
  116b02:	mov    %r13,0x38(%rdx)
  116b06:	mov    %eax,0x40(%rdx)
  116b09:	mov    0x38(%rsp),%eax
  116b0d:	mov    %eax,0x44(%rdx)
  116b10:	callq  11c7f0 <vim_free@@Base>
  116b15:	jmp    116aa2 <get_c_indent@@Base+0x2f2>
  116b17:	mov    0xa8(%rsp),%esi
  116b1e:	cmp    %esi,0x8(%rax)
  116b21:	jne    1168fd <get_c_indent@@Base+0x14d>
  116b27:	mov    0xac(%rsp),%esi
  116b2e:	cmp    %esi,0xc(%rax)
  116b31:	jmpq   1168fd <get_c_indent@@Base+0x14d>
  116b36:	movzbl 0x1(%r12),%eax
  116b3c:	cmp    $0x2f,%al
  116b3e:	je     116cd3 <get_c_indent@@Base+0x523>
  116b44:	cmp    $0x2a,%al
  116b46:	je     116b50 <get_c_indent@@Base+0x3a0>
  116b48:	cmp    $0x2f,%al
  116b4a:	jne    11694b <get_c_indent@@Base+0x19b>
  116b50:	mov    %r12,%rdi
  116b53:	callq  607e0 <skipwhite@@Base>
  116b58:	cmpb   $0x5d,(%rax)
  116b5b:	je     1175cf <get_c_indent@@Base+0xe1f>
  116b61:	mov    0x397210(%rip),%rax        # 4add78 <curbuf@@Base>
  116b68:	mov    $0x28,%edi
  116b6d:	mov    0x1664(%rax),%esi
  116b73:	callq  114130 <find_start_comment@@Base+0x150>
  116b78:	test   %rax,%rax
  116b7b:	mov    %rax,%rbx
  116b7e:	je     11782a <get_c_indent@@Base+0x107a>
  116b84:	mov    0x3971ed(%rip),%rax        # 4add78 <curbuf@@Base>
  116b8b:	mov    0x1674(%rax),%r14d
  116b92:	test   %r14d,%r14d
  116b95:	je     117019 <get_c_indent@@Base+0x869>
  116b9b:	callq  114240 <find_start_comment@@Base+0x260>
  116ba0:	test   %rax,%rax
  116ba3:	je     117019 <get_c_indent@@Base+0x869>
  116ba9:	mov    (%rax),%rsi
  116bac:	cmp    %rsi,(%rbx)
  116baf:	je     11760f <get_c_indent@@Base+0xe5f>
  116bb5:	setl   %dl
  116bb8:	test   %dl,%dl
  116bba:	je     117019 <get_c_indent@@Base+0x869>
  116bc0:	mov    (%rax),%rdx
  116bc3:	mov    0x8(%rax),%rcx
  116bc7:	mov    %rdx,%rdi
  116bca:	mov    %rdx,0xa0(%rsp)
  116bd2:	mov    %rcx,0xa8(%rsp)
  116bda:	mov    %rdx,0x30(%rsp)
  116bdf:	callq  1007a0 <ml_get@@Base>
  116be4:	mov    %rax,%rdi
  116be7:	mov    %rax,%rbp
  116bea:	callq  607e0 <skipwhite@@Base>
  116bef:	mov    %rax,0x90(%rsp)
  116bf7:	cmpb   $0x7b,(%rax)
  116bfa:	je     117f70 <get_c_indent@@Base+0x17c0>
  116c00:	mov    0x30(%rsp),%rsi
  116c05:	mov    0x397b04(%rip),%rax        # 4ae710 <curwin@@Base>
  116c0c:	mov    $0x29,%edx
  116c11:	mov    %rbp,%rdi
  116c14:	mov    %rsi,0x38(%rax)
  116c18:	mov    %rsi,0x98(%rsp)
  116c20:	mov    $0x28,%esi
  116c25:	callq  10e490 <smsg_attr@@Base+0x9f0>
  116c2a:	test   %eax,%eax
  116c2c:	jne    117f3f <get_c_indent@@Base+0x178f>
  116c32:	mov    0x39713f(%rip),%rax        # 4add78 <curbuf@@Base>
  116c39:	cmpq   $0x0,0x1678(%rax)
  116c41:	jne    117f14 <get_c_indent@@Base+0x1764>
  116c47:	mov    0x1678(%rax),%esi
  116c4d:	test   %esi,%esi
  116c4f:	je     117ef0 <get_c_indent@@Base+0x1740>
  116c55:	mov    0x98(%rsp),%rdi
  116c5d:	callq  10ef90 <get_indent_lnum@@Base>
  116c62:	movl   $0x3,0x44(%rsp)
  116c6a:	mov    %eax,%ebx
  116c6c:	mov    0x397105(%rip),%rax        # 4add78 <curbuf@@Base>
  116c73:	mov    0x1678(%rax),%ebp
  116c79:	test   %ebp,%ebp
  116c7b:	je     116c87 <get_c_indent@@Base+0x4d7>
  116c7d:	mov    %r12,%rdi
  116c80:	callq  10e010 <smsg_attr@@Base+0x570>
  116c85:	mov    %eax,%ebp
  116c87:	cmpb   $0x7d,(%r12)
  116c8c:	jne    117b1e <get_c_indent@@Base+0x136e>
  116c92:	mov    0x3970df(%rip),%rax        # 4add78 <curbuf@@Base>
  116c99:	add    0x1614(%rax),%ebx
  116c9f:	mov    %ebx,(%rsp)
  116ca2:	mov    0x397a67(%rip),%rdx        # 4ae710 <curwin@@Base>
  116ca9:	test   %r15d,%r15d
  116cac:	mov    0x161c(%rax),%eax
  116cb2:	je     117129 <get_c_indent@@Base+0x979>
  116cb8:	mov    (%rsp),%ebx
  116cbb:	test   %eax,%eax
  116cbd:	setg   %cl
  116cc0:	mov    %ebx,%esi
  116cc2:	sub    %eax,%esi
  116cc4:	test   %cl,%cl
  116cc6:	mov    %esi,%eax
  116cc8:	cmove  %ebx,%eax
  116ccb:	mov    %eax,(%rsp)
  116cce:	jmpq   117129 <get_c_indent@@Base+0x979>
  116cd3:	mov    0x397a36(%rip),%rax        # 4ae710 <curwin@@Base>
  116cda:	lea    0x38d94f(%rip),%rbp        # 4a4630 <current_funccal@@Base+0x2d28>
  116ce1:	mov    0x40(%rax),%rdx
  116ce5:	mov    0x38(%rax),%rax
  116ce9:	mov    %rdx,0x38d948(%rip)        # 4a4638 <current_funccal@@Base+0x2d30>
  116cf0:	mov    %rax,0x38d939(%rip)        # 4a4630 <current_funccal@@Base+0x2d28>
  116cf7:	nopw   0x0(%rax,%rax,1)
  116d00:	mov    0x0(%rbp),%rax
  116d04:	lea    -0x1(%rax),%rdi
  116d08:	test   %rdi,%rdi
  116d0b:	mov    %rdi,0x0(%rbp)
  116d0f:	jle    116d38 <get_c_indent@@Base+0x588>
  116d11:	callq  1007a0 <ml_get@@Base>
  116d16:	mov    %rax,%rdi
  116d19:	mov    %rax,%rbx
  116d1c:	callq  607e0 <skipwhite@@Base>
  116d21:	movzbl (%rax),%edx
  116d24:	cmp    $0x2f,%dl
  116d27:	je     116fd0 <get_c_indent@@Base+0x820>
  116d2d:	test   %dl,%dl
  116d2f:	je     116d00 <get_c_indent@@Base+0x550>
  116d31:	nopl   0x0(%rax)
  116d38:	cmpb   $0x2f,(%r12)
  116d3d:	jne    11694b <get_c_indent@@Base+0x19b>
  116d43:	movzbl 0x1(%r12),%eax
  116d49:	jmpq   116b44 <get_c_indent@@Base+0x394>
  116d4e:	xchg   %ax,%ax
  116d50:	lea    0x1(%rdx),%rcx
  116d54:	mov    %rcx,0xb0(%rsp)
  116d5c:	movzbl (%rdx),%ebx
  116d5f:	mov    %rcx,%rdx
  116d62:	jmpq   116a68 <get_c_indent@@Base+0x2b8>
  116d67:	nopw   0x0(%rax,%rax,1)
  116d70:	cmp    $0x3a,%al
  116d72:	je     116dd0 <get_c_indent@@Base+0x620>
  116d74:	lea    0x10f5c2(%rip),%rcx        # 22633d <_IO_stdin_used@@Base+0xfd7d>
  116d7b:	mov    $0x32,%edx
  116d80:	mov    %r14,%rsi
  116d83:	mov    %r13,%rdi
  116d86:	callq  11c920 <copy_option_part@@Base>
  116d8b:	cmp    $0x73,%r15d
  116d8f:	je     116f80 <get_c_indent@@Base+0x7d0>
  116d95:	cmp    $0x6d,%r15d
  116d99:	je     116fb0 <get_c_indent@@Base+0x800>
  116d9f:	cmp    $0x65,%r15d
  116da3:	je     116de0 <get_c_indent@@Base+0x630>
  116da5:	mov    0xb0(%rsp),%rdx
  116dad:	jmpq   116a18 <get_c_indent@@Base+0x268>
  116db2:	nopw   0x0(%rax,%rax,1)
  116db8:	mov    %r13,%rdi
  116dbb:	callq  60c70 <getdigits@@Base>
  116dc0:	mov    0xb0(%rsp),%rdx
  116dc8:	mov    %eax,%ebp
  116dca:	jmpq   116a68 <get_c_indent@@Base+0x2b8>
  116dcf:	nop
  116dd0:	add    $0x1,%rdx
  116dd4:	mov    %rdx,0xb0(%rsp)
  116ddc:	jmp    116d74 <get_c_indent@@Base+0x5c4>
  116dde:	xchg   %ax,%ax
  116de0:	movslq 0x18(%rsp),%r15
  116de5:	mov    0x28(%rsp),%rdi
  116dea:	mov    %r12,%rsi
  116ded:	mov    %r15,%rdx
  116df0:	callq  4ec90 <_init@@Base+0xa0>
  116df5:	test   %eax,%eax
  116df7:	mov    %r14,%rdx
  116dfa:	je     116e80 <get_c_indent@@Base+0x6d0>
  116e00:	mov    (%rdx),%ecx
  116e02:	add    $0x4,%rdx
  116e06:	lea    -0x1010101(%rcx),%eax
  116e0c:	not    %ecx
  116e0e:	and    %ecx,%eax
  116e10:	and    $0x80808080,%eax
  116e15:	je     116e00 <get_c_indent@@Base+0x650>
  116e17:	mov    %eax,%ecx
  116e19:	mov    0x28(%rsp),%rdi
  116e1e:	shr    $0x10,%ecx
  116e21:	test   $0x8080,%eax
  116e26:	cmove  %ecx,%eax
  116e29:	lea    0x2(%rdx),%rcx
  116e2d:	mov    %eax,%esi
  116e2f:	cmove  %rcx,%rdx
  116e33:	add    %al,%sil
  116e36:	mov    %r14,%rsi
  116e39:	sbb    $0x3,%rdx
  116e3d:	sub    %r14,%rdx
  116e40:	callq  4ec90 <_init@@Base+0xa0>
  116e45:	test   %eax,%eax
  116e47:	jne    116da5 <get_c_indent@@Base+0x5f5>
  116e4d:	mov    0x3978bc(%rip),%rax        # 4ae710 <curwin@@Base>
  116e54:	mov    0x48(%rsp),%r13
  116e59:	mov    0x38(%rax),%rdi
  116e5d:	sub    $0x1,%rdi
  116e61:	callq  10ef90 <get_indent_lnum@@Base>
  116e66:	test   %ebp,%ebp
  116e68:	mov    %eax,(%rsp)
  116e6b:	je     117935 <get_c_indent@@Base+0x1185>
  116e71:	add    %ebp,%eax
  116e73:	mov    %eax,(%rsp)
  116e76:	jmpq   116f72 <get_c_indent@@Base+0x7c2>
  116e7b:	nopl   0x0(%rax,%rax,1)
  116e80:	mov    (%rdx),%ecx
  116e82:	add    $0x4,%rdx
  116e86:	lea    -0x1010101(%rcx),%eax
  116e8c:	not    %ecx
  116e8e:	and    %ecx,%eax
  116e90:	and    $0x80808080,%eax
  116e95:	je     116e80 <get_c_indent@@Base+0x6d0>
  116e97:	mov    %eax,%ecx
  116e99:	mov    0x28(%rsp),%rdi
  116e9e:	shr    $0x10,%ecx
  116ea1:	test   $0x8080,%eax
  116ea6:	cmove  %ecx,%eax
  116ea9:	lea    0x2(%rdx),%rcx
  116ead:	mov    %eax,%esi
  116eaf:	cmove  %rcx,%rdx
  116eb3:	add    %al,%sil
  116eb6:	mov    %r14,%rsi
  116eb9:	sbb    $0x3,%rdx
  116ebd:	sub    %r14,%rdx
  116ec0:	callq  4ec90 <_init@@Base+0xa0>
  116ec5:	test   %eax,%eax
  116ec7:	je     116da5 <get_c_indent@@Base+0x5f5>
  116ecd:	mov    0x39783c(%rip),%rax        # 4ae710 <curwin@@Base>
  116ed4:	mov    0x38(%rax),%rax
  116ed8:	cmp    $0x1,%rax
  116edc:	jle    116f56 <get_c_indent@@Base+0x7a6>
  116ede:	lea    -0x1(%rax),%rdi
  116ee2:	callq  1007a0 <ml_get@@Base>
  116ee7:	mov    %rax,%rdi
  116eea:	callq  607e0 <skipwhite@@Base>
  116eef:	movslq 0x3c(%rsp),%rbx
  116ef4:	mov    0x30(%rsp),%rsi
  116ef9:	mov    %rax,%rdi
  116efc:	mov    %rax,%rbp
  116eff:	mov    %rax,0x90(%rsp)
  116f07:	mov    %rbx,%rdx
  116f0a:	callq  4ec90 <_init@@Base+0xa0>
  116f0f:	test   %eax,%eax
  116f11:	je     117a6e <get_c_indent@@Base+0x12be>
  116f17:	mov    %r15,%rdx
  116f1a:	mov    %r12,%rsi
  116f1d:	mov    %rbp,%rdi
  116f20:	callq  4ec90 <_init@@Base+0xa0>
  116f25:	test   %eax,%eax
  116f27:	je     117a4d <get_c_indent@@Base+0x129d>
  116f2d:	mov    0x20(%rsp),%r15
  116f32:	mov    (%r15),%rdi
  116f35:	callq  1007a0 <ml_get@@Base>
  116f3a:	movslq 0x8(%r15),%rdi
  116f3e:	mov    0x30(%rsp),%rsi
  116f43:	mov    %rbx,%rdx
  116f46:	add    %rax,%rdi
  116f49:	callq  4ec90 <_init@@Base+0xa0>
  116f4e:	test   %eax,%eax
  116f50:	jne    117330 <get_c_indent@@Base+0xb80>
  116f56:	mov    0x48(%rsp),%r13
  116f5b:	mov    0x40(%rsp),%eax
  116f5f:	test   %eax,%eax
  116f61:	jne    1175a9 <get_c_indent@@Base+0xdf9>
  116f67:	cmpl   $0x72,0x44(%rsp)
  116f6c:	je     11793e <get_c_indent@@Base+0x118e>
  116f72:	mov    0x397797(%rip),%rdx        # 4ae710 <curwin@@Base>
  116f79:	jmpq   117129 <get_c_indent@@Base+0x979>
  116f7e:	xchg   %ax,%ax
  116f80:	mov    0x30(%rsp),%r15
  116f85:	mov    $0x32,%edx
  116f8a:	mov    %r14,%rsi
  116f8d:	mov    %r15,%rdi
  116f90:	callq  4efa0 <_init@@Base+0x3b0>
  116f95:	sub    %r15d,%eax
  116f98:	mov    %ebp,0x40(%rsp)
  116f9c:	mov    %ebx,0x44(%rsp)
  116fa0:	mov    %eax,0x3c(%rsp)
  116fa4:	jmpq   116da5 <get_c_indent@@Base+0x5f5>
  116fa9:	nopl   0x0(%rax)
  116fb0:	mov    $0x32,%edx
  116fb5:	mov    %r14,%rsi
  116fb8:	mov    %r12,%rdi
  116fbb:	callq  4efa0 <_init@@Base+0x3b0>
  116fc0:	sub    %r12d,%eax
  116fc3:	mov    %eax,0x18(%rsp)
  116fc7:	jmpq   116da5 <get_c_indent@@Base+0x5f5>
  116fcc:	nopl   0x0(%rax)
  116fd0:	cmpb   $0x2f,0x1(%rax)
  116fd4:	jne    116d38 <get_c_indent@@Base+0x588>
  116fda:	mov    0x39772f(%rip),%rdi        # 4ae710 <curwin@@Base>
  116fe1:	lea    0x84(%rsp),%rdx
  116fe9:	lea    0x38d640(%rip),%rsi        # 4a4630 <current_funccal@@Base+0x2d28>
  116ff0:	sub    %rbx,%rax
  116ff3:	xor    %r8d,%r8d
  116ff6:	xor    %ecx,%ecx
  116ff8:	mov    %eax,0x38d63a(%rip)        # 4a4638 <current_funccal@@Base+0x2d30>
  116ffe:	callq  60170 <getvcol@@Base>
  117003:	mov    0x84(%rsp),%eax
  11700a:	mov    0x3976ff(%rip),%rdx        # 4ae710 <curwin@@Base>
  117011:	mov    %eax,(%rsp)
  117014:	jmpq   117129 <get_c_indent@@Base+0x979>
  117019:	cmpb   $0x29,(%r12)
  11701e:	je     117345 <get_c_indent@@Base+0xb95>
  117024:	mov    (%rbx),%rax
  117027:	mov    0x8(%rbx),%rcx
  11702b:	lea    -0x1(%r13),%rdi
  11702f:	mov    %rdi,0x98(%rsp)
  117037:	cmp    %rax,%rdi
  11703a:	mov    %rax,%rdx
  11703d:	mov    %rax,0xb0(%rsp)
  117045:	mov    %rcx,0xb8(%rsp)
  11704d:	jle    1171d8 <get_c_indent@@Base+0xa28>
  117053:	lea    0x98(%rsp),%rbp
  11705b:	lea    0x88(%rsp),%rbx
  117063:	jmp    11708d <get_c_indent@@Base+0x8dd>
  117065:	nopl   (%rax)
  117068:	mov    0xb0(%rsp),%rdx
  117070:	mov    0x98(%rsp),%rdi
  117078:	sub    $0x1,%rdi
  11707c:	cmp    %rdx,%rdi
  11707f:	mov    %rdi,0x98(%rsp)
  117087:	jle    1171d8 <get_c_indent@@Base+0xa28>
  11708d:	callq  1007a0 <ml_get@@Base>
  117092:	mov    %rax,%rdi
  117095:	callq  607e0 <skipwhite@@Base>
  11709a:	mov    %rax,%rdi
  11709d:	mov    %rax,0x88(%rsp)
  1170a5:	callq  10db80 <smsg_attr@@Base+0xe0>
  1170aa:	cmpb   $0x0,(%rax)
  1170ad:	je     117068 <get_c_indent@@Base+0x8b8>
  1170af:	mov    %rbp,%rsi
  1170b2:	mov    %rbx,%rdi
  1170b5:	callq  10dc40 <smsg_attr@@Base+0x1a0>
  1170ba:	test   %eax,%eax
  1170bc:	jne    117068 <get_c_indent@@Base+0x8b8>
  1170be:	mov    0x98(%rsp),%rdx
  1170c6:	mov    0x397643(%rip),%rax        # 4ae710 <curwin@@Base>
  1170cd:	mov    %rdx,0x38(%rax)
  1170d1:	callq  114080 <find_start_comment@@Base+0xa0>
  1170d6:	test   %rax,%rax
  1170d9:	je     11713b <get_c_indent@@Base+0x98b>
  1170db:	mov    (%rax),%rdi
  1170de:	mov    0xb0(%rsp),%rdx
  1170e6:	add    $0x1,%rdi
  1170ea:	jmp    117078 <get_c_indent@@Base+0x8c8>
  1170ec:	mov    0x8(%rsp),%rax
  1170f1:	cmpb   $0x23,(%rax)
  1170f4:	je     117112 <get_c_indent@@Base+0x962>
  1170f6:	mov    $0x1,%edx
  1170fb:	mov    $0x20,%esi
  117100:	mov    $0x23,%edi
  117105:	callq  70700 <in_cinkeys@@Base>
  11710a:	test   %eax,%eax
  11710c:	je     11691b <get_c_indent@@Base+0x16b>
  117112:	mov    0x396c5f(%rip),%rax        # 4add78 <curbuf@@Base>
  117119:	mov    0x3975f0(%rip),%rdx        # 4ae710 <curwin@@Base>
  117120:	mov    0x1680(%rax),%eax
  117126:	mov    %eax,(%rsp)
  117129:	mov    (%rsp),%eax
  11712c:	mov    $0x0,%ebx
  117131:	test   %eax,%eax
  117133:	cmovns %eax,%ebx
  117136:	jmpq   116af9 <get_c_indent@@Base+0x349>
  11713b:	mov    0x3975ce(%rip),%rax        # 4ae710 <curwin@@Base>
  117142:	mov    %r13,%rdx
  117145:	sub    0x38(%rax),%rdx
  117149:	mov    0x396c28(%rip),%rax        # 4add78 <curbuf@@Base>
  117150:	mov    0x1664(%rax),%esi
  117156:	test   %rdx,%rdx
  117159:	jle    117170 <get_c_indent@@Base+0x9c0>
  11715b:	mov    %esi,%eax
  11715d:	mov    %esi,%ecx
  11715f:	shr    $0x1f,%eax
  117162:	sub    %edx,%ecx
  117164:	add    %esi,%eax
  117166:	sar    %eax
  117168:	cltq   
  11716a:	cmp    %rax,%rdx
  11716d:	cmovl  %ecx,%esi
  117170:	mov    $0x28,%edi
  117175:	callq  114130 <find_start_comment@@Base+0x150>
  11717a:	test   %rax,%rax
  11717d:	mov    0xb0(%rsp),%rdx
  117185:	je     117070 <get_c_indent@@Base+0x8c0>
  11718b:	cmp    %rdx,(%rax)
  11718e:	jne    117070 <get_c_indent@@Base+0x8c0>
  117194:	mov    0xb8(%rsp),%esi
  11719b:	cmp    %esi,0x8(%rax)
  11719e:	mov    0x98(%rsp),%rdi
  1171a6:	jne    117078 <get_c_indent@@Base+0x8c8>
  1171ac:	callq  10ef90 <get_indent_lnum@@Base>
  1171b1:	cmpb   $0x29,(%r12)
  1171b6:	mov    %eax,(%rsp)
  1171b9:	jne    117371 <get_c_indent@@Base+0xbc1>
  1171bf:	mov    0xb0(%rsp),%rdx
  1171c7:	cmp    %rdx,0x98(%rsp)
  1171cf:	je     1171d8 <get_c_indent@@Base+0xa28>
  1171d1:	cmp    $0x7fffffff,%eax
  1171d6:	jne    1171df <get_c_indent@@Base+0xa2f>
  1171d8:	movl   $0x7fffffff,(%rsp)
  1171df:	mov    0x396b92(%rip),%rsi        # 4add78 <curbuf@@Base>
  1171e6:	mov    0x1688(%rsi),%r14d
  1171ed:	test   %r14d,%r14d
  1171f0:	jne    1173d5 <get_c_indent@@Base+0xc25>
  1171f6:	lea    0x90(%rsp),%rsi
  1171fe:	mov    %rdx,%rdi
  117201:	xor    %ebp,%ebp
  117203:	callq  116700 <cin_islabel@@Base+0x190>
  117208:	mov    0x90(%rsp),%rdi
  117210:	mov    %eax,%ebx
  117212:	callq  607e0 <skipwhite@@Base>
  117217:	mov    %rax,0x90(%rsp)
  11721f:	cmpb   $0x28,(%rax)
  117222:	je     117fad <get_c_indent@@Base+0x17fd>
  117228:	cmpb   $0x29,(%r12)
  11722d:	je     117749 <get_c_indent@@Base+0xf99>
  117233:	mov    0x396b3e(%rip),%rax        # 4add78 <curbuf@@Base>
  11723a:	mov    %r14d,%esi
  11723d:	or     0x1648(%rax),%esi
  117243:	je     11726e <get_c_indent@@Base+0xabe>
  117245:	mov    0x1650(%rax),%r11d
  11724c:	test   %r11d,%r11d
  11724f:	jne    11761a <get_c_indent@@Base+0xe6a>
  117255:	mov    0x90(%rsp),%rdx
  11725d:	cmpb   $0x28,(%rdx)
  117260:	jne    11761a <get_c_indent@@Base+0xe6a>
  117266:	test   %ebp,%ebp
  117268:	jne    11761a <get_c_indent@@Base+0xe6a>
  11726e:	mov    0xb0(%rsp),%rdi
  117276:	callq  1007a0 <ml_get@@Base>
  11727b:	mov    0x396af6(%rip),%r8        # 4add78 <curbuf@@Base>
  117282:	mov    %rax,0x88(%rsp)
  11728a:	mov    0x1654(%r8),%r10d
  117291:	test   %r10d,%r10d
  117294:	jne    117a8f <get_c_indent@@Base+0x12df>
  11729a:	mov    0x1658(%r8),%r9d
  1172a1:	test   %r9d,%r9d
  1172a4:	je     117971 <get_c_indent@@Base+0x11c1>
  1172aa:	mov    0xb8(%rsp),%eax
  1172b1:	lea    0x1(%rax),%ecx
  1172b4:	mov    %ecx,0xb8(%rsp)
  1172bb:	test   %ecx,%ecx
  1172bd:	movl   $0x7fffffff,(%rsp)
  1172c4:	mov    %r8,%rax
  1172c7:	jle    117303 <get_c_indent@@Base+0xb53>
  1172c9:	mov    0x397440(%rip),%rdi        # 4ae710 <curwin@@Base>
  1172d0:	lea    0xb0(%rsp),%rsi
  1172d8:	lea    0x84(%rsp),%rdx
  1172e0:	xor    %r8d,%r8d
  1172e3:	xor    %ecx,%ecx
  1172e5:	callq  60170 <getvcol@@Base>
  1172ea:	mov    (%rsp),%esi
  1172ed:	mov    0x84(%rsp),%eax
  1172f4:	cmp    %eax,%esi
  1172f6:	cmovle %esi,%eax
  1172f9:	mov    %eax,(%rsp)
  1172fc:	mov    0x396a75(%rip),%rax        # 4add78 <curbuf@@Base>
  117303:	cmpb   $0x29,(%r12)
  117308:	je     11775f <get_c_indent@@Base+0xfaf>
  11730e:	mov    0x1648(%rax),%edx
  117314:	or     %r14d,%edx
  117317:	test   %edx,%edx
  117319:	jne    11761a <get_c_indent@@Base+0xe6a>
  11731f:	mov    (%rsp),%esi
  117322:	cmp    $0x7fffffff,%esi
  117328:	cmovne %esi,%ebx
  11732b:	mov    %ebx,(%rsp)
  11732e:	jmp    117382 <get_c_indent@@Base+0xbd2>
  117330:	movl   $0x1,0x50(%rsp)
  117338:	jmpq   116da5 <get_c_indent@@Base+0x5f5>
  11733d:	movb   $0x0,(%rax)
  117340:	jmpq   116880 <get_c_indent@@Base+0xd0>
  117345:	mov    0x396a2c(%rip),%rax        # 4add78 <curbuf@@Base>
  11734c:	mov    0x1660(%rax),%ebp
  117352:	test   %ebp,%ebp
  117354:	je     117024 <get_c_indent@@Base+0x874>
  11735a:	mov    0x3973af(%rip),%rax        # 4ae710 <curwin@@Base>
  117361:	mov    0x38(%rax),%rdi
  117365:	sub    $0x1,%rdi
  117369:	callq  10ef90 <get_indent_lnum@@Base>
  11736e:	mov    %eax,(%rsp)
  117371:	cmpl   $0xffffffff,(%rsp)
  117375:	je     118880 <get_c_indent@@Base+0x20d0>
  11737b:	mov    0x3969f6(%rip),%rax        # 4add78 <curbuf@@Base>
  117382:	cmpb   $0x2f,(%r12)
  117387:	jne    116ca2 <get_c_indent@@Base+0x4f2>
  11738d:	movzbl 0x1(%r12),%edx
  117393:	cmp    $0x2a,%dl
  117396:	sete   %cl
  117399:	cmp    $0x2f,%dl
  11739c:	sete   %dl
  11739f:	or     %dl,%cl
  1173a1:	je     1173ac <get_c_indent@@Base+0xbfc>
  1173a3:	mov    0x1634(%rax),%ebx
  1173a9:	add    %ebx,(%rsp)
  1173ac:	mov    0x39735d(%rip),%rdx        # 4ae710 <curwin@@Base>
  1173b3:	test   %cl,%cl
  1173b5:	je     116ca9 <get_c_indent@@Base+0x4f9>
  1173bb:	mov    0x1634(%rax),%ebx
  1173c1:	add    %ebx,(%rsp)
  1173c4:	jmpq   116ca9 <get_c_indent@@Base+0x4f9>
  1173c9:	mov    0x397340(%rip),%rdx        # 4ae710 <curwin@@Base>
  1173d0:	jmpq   116af9 <get_c_indent@@Base+0x349>
  1173d5:	mov    0x397334(%rip),%rcx        # 4ae710 <curwin@@Base>
  1173dc:	mov    %rdx,%r14
  1173df:	mov    0x38(%rcx),%rax
  1173e3:	mov    0x44(%rcx),%ebx
  1173e6:	mov    0x40(%rcx),%ebp
  1173e9:	mov    %rax,0x18(%rsp)
  1173ee:	mov    %ebx,0x20(%rsp)
  1173f2:	lea    0xb0(%rsp),%rax
  1173fa:	jmp    117413 <get_c_indent@@Base+0xc63>
  1173fc:	nopl   0x0(%rax)
  117400:	cmp    %r14,(%rax)
  117403:	jne    117432 <get_c_indent@@Base+0xc82>
  117405:	mov    0x397304(%rip),%rcx        # 4ae710 <curwin@@Base>
  11740c:	mov    0x396965(%rip),%rsi        # 4add78 <curbuf@@Base>
  117413:	mov    0x8(%rax),%ebx
  117416:	mov    0x1664(%rsi),%esi
  11741c:	mov    $0x28,%edi
  117421:	mov    %r14,0x38(%rcx)
  117425:	mov    %ebx,0x40(%rcx)
  117428:	callq  114130 <find_start_comment@@Base+0x150>
  11742d:	test   %rax,%rax
  117430:	jne    117400 <get_c_indent@@Base+0xc50>
  117432:	mov    0x3972d7(%rip),%rax        # 4ae710 <curwin@@Base>
  117439:	mov    %r14,%rdx
  11743c:	mov    0x18(%rsp),%rsi
  117441:	mov    %ebx,%r14d
  117444:	mov    0x20(%rsp),%ebx
  117448:	mov    %rdx,%rdi
  11744b:	mov    %rsi,0x38(%rax)
  11744f:	mov    %ebp,0x40(%rax)
  117452:	mov    %ebx,0x44(%rax)
  117455:	callq  1007a0 <ml_get@@Base>
  11745a:	cmp    $0x1,%r14d
  11745e:	lea    -0x1(%r14),%r8d
  117462:	jle    117969 <get_c_indent@@Base+0x11b9>
  117468:	cmp    $0x2,%r8d
  11746c:	jle    1174a9 <get_c_indent@@Base+0xcf9>
  11746e:	movslq %r8d,%rdx
  117471:	movzbl (%rax,%rdx,1),%edx
  117475:	cmp    $0x9,%dl
  117478:	je     11747f <get_c_indent@@Base+0xccf>
  11747a:	cmp    $0x20,%dl
  11747d:	jne    1174a9 <get_c_indent@@Base+0xcf9>
  11747f:	lea    -0x2(%r14),%edx
  117483:	lea    0x1(%rax),%rsi
  117487:	movslq %edx,%rdx
  11748a:	cmp    $0x2,%edx
  11748d:	mov    %edx,%r8d
  117490:	je     1177a8 <get_c_indent@@Base+0xff8>
  117496:	movzbl -0x1(%rsi,%rdx,1),%ecx
  11749b:	sub    $0x1,%rdx
  11749f:	cmp    $0x20,%cl
  1174a2:	je     11748a <get_c_indent@@Base+0xcda>
  1174a4:	cmp    $0x9,%cl
  1174a7:	je     11748a <get_c_indent@@Base+0xcda>
  1174a9:	lea    -0x1(%r8),%edx
  1174ad:	lea    0x10870d(%rip),%rdi        # 21fbc1 <_IO_stdin_used@@Base+0x9601>
  1174b4:	mov    $0x2,%ecx
  1174b9:	movslq %edx,%r9
  1174bc:	lea    (%rax,%r9,1),%rsi
  1174c0:	repz cmpsb %es:(%rdi),%ds:(%rsi)
  1174c2:	jne    117961 <get_c_indent@@Base+0x11b1>
  1174c8:	test   %edx,%edx
  1174ca:	jne    117a34 <get_c_indent@@Base+0x1284>
  1174d0:	mov    $0x1,%r14d
  1174d6:	mov    0xb0(%rsp),%rdx
  1174de:	jmpq   1171f6 <get_c_indent@@Base+0xa46>
  1174e3:	mov    0x50(%rsp),%eax
  1174e7:	mov    0x48(%rsp),%r13
  1174ec:	mov    0x28(%rsp),%r12
  1174f1:	test   %eax,%eax
  1174f3:	jne    116f72 <get_c_indent@@Base+0x7c2>
  1174f9:	cmpb   $0x2a,(%r12)
  1174fe:	je     117606 <get_c_indent@@Base+0xe56>
  117504:	mov    0x20(%rsp),%rax
  117509:	lea    -0x1(%r13),%rdi
  11750d:	mov    0x20(%rsp),%rbx
  117512:	mov    %rdi,0x98(%rsp)
  11751a:	cmp    (%rax),%rdi
  11751d:	jle    117545 <get_c_indent@@Base+0xd95>
  11751f:	callq  199830 <linewhite@@Base>
  117524:	test   %eax,%eax
  117526:	je     1175b1 <get_c_indent@@Base+0xe01>
  11752c:	mov    0x98(%rsp),%rax
  117534:	lea    -0x1(%rax),%rdi
  117538:	cmp    %rdi,(%rbx)
  11753b:	mov    %rdi,0x98(%rsp)
  117543:	jl     11751f <get_c_indent@@Base+0xd6f>
  117545:	mov    0x39682c(%rip),%rax        # 4add78 <curbuf@@Base>
  11754c:	mov    0x163c(%rax),%eax
  117552:	test   %eax,%eax
  117554:	je     1179da <get_c_indent@@Base+0x122a>
  11755a:	mov    0x60(%rsp),%rdx
  11755f:	mov    0x20(%rsp),%rsi
  117564:	xor    %r8d,%r8d
  117567:	mov    0x3971a2(%rip),%rdi        # 4ae710 <curwin@@Base>
  11756e:	xor    %ecx,%ecx
  117570:	callq  60170 <getvcol@@Base>
  117575:	mov    0x84(%rsp),%eax
  11757c:	mov    %eax,(%rsp)
  11757f:	mov    0x3967f2(%rip),%rax        # 4add78 <curbuf@@Base>
  117586:	mov    0x163c(%rax),%r15d
  11758d:	test   %r15d,%r15d
  117590:	jne    1175a3 <get_c_indent@@Base+0xdf3>
  117592:	mov    0x90(%rsp),%rdx
  11759a:	cmpb   $0x0,(%rdx)
  11759d:	jne    116f72 <get_c_indent@@Base+0x7c2>
  1175a3:	mov    0x1638(%rax),%eax
  1175a9:	add    %eax,(%rsp)
  1175ac:	jmpq   116f72 <get_c_indent@@Base+0x7c2>
  1175b1:	mov    0x98(%rsp),%rdi
  1175b9:	callq  10ef90 <get_indent_lnum@@Base>
  1175be:	cmp    $0xffffffff,%eax
  1175c1:	mov    %eax,(%rsp)
  1175c4:	jne    116f72 <get_c_indent@@Base+0x7c2>
  1175ca:	jmpq   117545 <get_c_indent@@Base+0xd95>
  1175cf:	mov    0x3967a2(%rip),%rax        # 4add78 <curbuf@@Base>
  1175d6:	mov    $0x5b,%edi
  1175db:	mov    0x1664(%rax),%esi
  1175e1:	callq  114130 <find_start_comment@@Base+0x150>
  1175e6:	test   %rax,%rax
  1175e9:	je     116b61 <get_c_indent@@Base+0x3b1>
  1175ef:	mov    (%rax),%rdi
  1175f2:	callq  10ef90 <get_indent_lnum@@Base>
  1175f7:	mov    0x397112(%rip),%rdx        # 4ae710 <curwin@@Base>
  1175fe:	mov    %eax,(%rsp)
  117601:	jmpq   117129 <get_c_indent@@Base+0x979>
  117606:	addl   $0x1,(%rsp)
  11760a:	jmpq   116f72 <get_c_indent@@Base+0x7c2>
  11760f:	mov    0x8(%rax),%esi
  117612:	cmp    %esi,0x8(%rbx)
  117615:	jmpq   116bb5 <get_c_indent@@Base+0x405>
  11761a:	mov    0x1650(%rax),%edi
  117620:	test   %edi,%edi
  117622:	jne    117639 <get_c_indent@@Base+0xe89>
  117624:	mov    0x90(%rsp),%rdx
  11762c:	cmpb   $0x28,(%rdx)
  11762f:	jne    117639 <get_c_indent@@Base+0xe89>
  117631:	test   %ebp,%ebp
  117633:	je     11731f <get_c_indent@@Base+0xb6f>
  117639:	mov    0xb8(%rsp),%eax
  117640:	lea    0xb0(%rsp),%rsi
  117648:	mov    %rsi,0x18(%rsp)
  11764d:	mov    %eax,0x84(%rsp)
  117654:	cmp    %eax,%ebp
  117656:	jge    11769e <get_c_indent@@Base+0xeee>
  117658:	mov    0x18(%rsp),%rdi
  11765d:	sub    $0x1,%eax
  117660:	mov    %eax,0xb8(%rsp)
  117667:	callq  1007c0 <ml_get_pos@@Base>
  11766c:	movzbl (%rax),%eax
  11766f:	cmp    $0x28,%al
  117671:	je     117729 <get_c_indent@@Base+0xf79>
  117677:	cmp    $0x29,%al
  117679:	jne    117693 <get_c_indent@@Base+0xee3>
  11767b:	mov    0x3966f6(%rip),%rax        # 4add78 <curbuf@@Base>
  117682:	movl   $0x7fffffff,0x84(%rsp)
  11768d:	sub    0x164c(%rax),%ebx
  117693:	mov    0xb8(%rsp),%eax
  11769a:	cmp    %eax,%ebp
  11769c:	jl     117658 <get_c_indent@@Base+0xea8>
  11769e:	mov    0x84(%rsp),%edx
  1176a5:	cmp    $0x7fffffff,%edx
  1176ab:	je     117818 <get_c_indent@@Base+0x1068>
  1176b1:	mov    0x397058(%rip),%rax        # 4ae710 <curwin@@Base>
  1176b8:	mov    0xb0(%rsp),%rcx
  1176c0:	mov    $0x28,%edi
  1176c5:	mov    %rcx,0x38(%rax)
  1176c9:	mov    %edx,0x40(%rax)
  1176cc:	mov    0x3966a5(%rip),%rax        # 4add78 <curbuf@@Base>
  1176d3:	mov    0x1664(%rax),%esi
  1176d9:	callq  114130 <find_start_comment@@Base+0x150>
  1176de:	test   %rax,%rax
  1176e1:	mov    %rax,%rbp
  1176e4:	je     11810a <get_c_indent@@Base+0x195a>
  1176ea:	callq  114240 <find_start_comment@@Base+0x260>
  1176ef:	test   %rax,%rax
  1176f2:	je     11770c <get_c_indent@@Base+0xf5c>
  1176f4:	mov    (%rax),%rsi
  1176f7:	cmp    %rsi,0x0(%rbp)
  1176fb:	je     11812a <get_c_indent@@Base+0x197a>
  117701:	setl   %al
  117704:	test   %al,%al
  117706:	jne    11810a <get_c_indent@@Base+0x195a>
  11770c:	mov    0x396665(%rip),%rax        # 4add78 <curbuf@@Base>
  117713:	add    0x164c(%rax),%ebx
  117719:	mov    (%rsp),%esi
  11771c:	cmp    %ebx,%esi
  11771e:	cmovle %esi,%ebx
  117721:	mov    %ebx,(%rsp)
  117724:	jmpq   117382 <get_c_indent@@Base+0xbd2>
  117729:	mov    0x396648(%rip),%rax        # 4add78 <curbuf@@Base>
  117730:	add    0x164c(%rax),%ebx
  117736:	mov    0xb8(%rsp),%eax
  11773d:	mov    %eax,0x84(%rsp)
  117744:	jmpq   117654 <get_c_indent@@Base+0xea4>
  117749:	mov    0xb8(%rsp),%ecx
  117750:	mov    0x396621(%rip),%rax        # 4add78 <curbuf@@Base>
  117757:	test   %ecx,%ecx
  117759:	jg     1172c9 <get_c_indent@@Base+0xb19>
  11775f:	mov    0x165c(%rax),%r8d
  117766:	test   %r8d,%r8d
  117769:	je     11730e <get_c_indent@@Base+0xb5e>
  11776f:	movzbl (%r12),%ecx
  117774:	mov    0x396f95(%rip),%rdx        # 4ae710 <curwin@@Base>
  11777b:	mov    %ebx,(%rsp)
  11777e:	cmp    $0x2f,%cl
  117781:	jne    116ca9 <get_c_indent@@Base+0x4f9>
  117787:	movzbl 0x1(%r12),%esi
  11778d:	cmp    $0x2a,%sil
  117791:	sete   %cl
  117794:	cmp    $0x2f,%sil
  117798:	sete   %sil
  11779c:	or     %esi,%ecx
  11779e:	jmpq   1173b3 <get_c_indent@@Base+0xc03>
  1177a3:	nopl   0x0(%rax,%rax,1)
  1177a8:	lea    0x108412(%rip),%rdi        # 21fbc1 <_IO_stdin_used@@Base+0x9601>
  1177af:	mov    $0x2,%ecx
  1177b4:	repz cmpsb %es:(%rdi),%ds:(%rsi)
  1177b6:	je     117a2e <get_c_indent@@Base+0x127e>
  1177bc:	lea    -0x2(%r8),%edx
  1177c0:	lea    0x123b4d(%rip),%rdi        # 23b314 <_IO_stdin_used@@Base+0x24d54>
  1177c7:	mov    $0x3,%ecx
  1177cc:	movslq %edx,%r9
  1177cf:	lea    (%rax,%r9,1),%rsi
  1177d3:	repz cmpsb %es:(%rdi),%ds:(%rsi)
  1177d5:	je     1174c8 <get_c_indent@@Base+0xd18>
  1177db:	cmp    $0x1,%edx
  1177de:	jle    117969 <get_c_indent@@Base+0x11b9>
  1177e4:	lea    -0x4(%r8),%edx
  1177e8:	lea    0x107b32(%rip),%rdi        # 21f321 <_IO_stdin_used@@Base+0x8d61>
  1177ef:	mov    $0x5,%ecx
  1177f4:	movslq %edx,%r9
  1177f7:	lea    (%rax,%r9,1),%rsi
  1177fb:	repz cmpsb %es:(%rdi),%ds:(%rsi)
  1177fd:	seta   %sil
  117801:	setb   %cl
  117804:	xor    %r14d,%r14d
  117807:	cmp    %cl,%sil
  11780a:	je     1174c8 <get_c_indent@@Base+0xd18>
  117810:	jmpq   1174d6 <get_c_indent@@Base+0xd26>
  117815:	nopl   (%rax)
  117818:	mov    0x396559(%rip),%rax        # 4add78 <curbuf@@Base>
  11781f:	add    0x1648(%rax),%ebx
  117825:	jmpq   117719 <get_c_indent@@Base+0xf69>
  11782a:	callq  114240 <find_start_comment@@Base+0x260>
  11782f:	test   %rax,%rax
  117832:	jne    116bc0 <get_c_indent@@Base+0x410>
  117838:	cmpb   $0x7b,(%r12)
  11783d:	je     118864 <get_c_indent@@Base+0x20b4>
  117843:	mov    0x39652e(%rip),%rax        # 4add78 <curbuf@@Base>
  11784a:	cmp    (%rax),%r13
  11784d:	jl     118894 <get_c_indent@@Base+0x20e4>
  117853:	mov    0x396eb6(%rip),%rdx        # 4ae710 <curwin@@Base>
  11785a:	mov    0x14(%rsp),%eax
  11785e:	lea    0x88(%rsp),%rbp
  117866:	lea    0xc0(%rsp),%r14
  11786e:	mov    %eax,0x40(%rdx)
  117871:	mov    0x38(%rsp),%eax
  117875:	mov    %r13,0x38(%rdx)
  117879:	mov    %eax,0x44(%rdx)
  11787c:	mov    %r13,%rax
  11787f:	jmp    1178a1 <get_c_indent@@Base+0x10f1>
  117881:	nopl   0x0(%rax)
  117888:	mov    (%rax),%rax
  11788b:	mov    0x396e7e(%rip),%rdx        # 4ae710 <curwin@@Base>
  117892:	add    $0x1,%rax
  117896:	movl   $0x0,0x40(%rdx)
  11789d:	mov    %rax,0x38(%rdx)
  1178a1:	cmp    $0x1,%rax
  1178a5:	jle    11873e <get_c_indent@@Base+0x1f8e>
  1178ab:	sub    $0x1,%rax
  1178af:	movl   $0x0,0x40(%rdx)
  1178b6:	mov    %rax,0x38(%rdx)
  1178ba:	callq  1007e0 <ml_get_curline@@Base>
  1178bf:	mov    %rax,0x88(%rsp)
  1178c7:	callq  114080 <find_start_comment@@Base+0xa0>
  1178cc:	test   %rax,%rax
  1178cf:	jne    117888 <get_c_indent@@Base+0x10d8>
  1178d1:	mov    0x3964a0(%rip),%rax        # 4add78 <curbuf@@Base>
  1178d8:	mov    0x1640(%rax),%esi
  1178de:	test   %esi,%esi
  1178e0:	je     117908 <get_c_indent@@Base+0x1158>
  1178e2:	cmpb   $0x7b,(%r12)
  1178e7:	je     117908 <get_c_indent@@Base+0x1158>
  1178e9:	mov    %r14,%rdi
  1178ec:	callq  505f2 <_init@@Base+0x1a02>
  1178f1:	mov    %eax,%ebx
  1178f3:	callq  1007e0 <ml_get_curline@@Base>
  1178f8:	test   %ebx,%ebx
  1178fa:	mov    %rax,0x88(%rsp)
  117902:	jne    11807a <get_c_indent@@Base+0x18ca>
  117908:	mov    0x396e01(%rip),%rax        # 4ae710 <curwin@@Base>
  11790f:	mov    %rbp,%rdi
  117912:	lea    0x38(%rax),%rsi
  117916:	callq  10dc40 <smsg_attr@@Base+0x1a0>
  11791b:	test   %eax,%eax
  11791d:	mov    %eax,%ebx
  11791f:	je     1186da <get_c_indent@@Base+0x1f2a>
  117925:	mov    0x396de4(%rip),%rdx        # 4ae710 <curwin@@Base>
  11792c:	mov    0x38(%rdx),%rax
  117930:	jmpq   1178a1 <get_c_indent@@Base+0x10f1>
  117935:	cmp    $0x72,%ebx
  117938:	jne    116f72 <get_c_indent@@Base+0x7c2>
  11793e:	lea    0xe0(%rsp),%rdi
  117946:	callq  5f010 <vim_strsize@@Base>
  11794b:	mov    0x58(%rsp),%rdi
  117950:	mov    %eax,%ebx
  117952:	callq  5f010 <vim_strsize@@Base>
  117957:	sub    %eax,%ebx
  117959:	add    %ebx,(%rsp)
  11795c:	jmpq   116f72 <get_c_indent@@Base+0x7c2>
  117961:	test   %edx,%edx
  117963:	jg     1177bc <get_c_indent@@Base+0x100c>
  117969:	xor    %r14d,%r14d
  11796c:	jmpq   1174d6 <get_c_indent@@Base+0xd26>
  117971:	mov    0xb8(%rsp),%edx
  117978:	mov    0x88(%rsp),%rax
  117980:	lea    0x1(%rdx),%edi
  117983:	movslq %edi,%rcx
  117986:	mov    %edi,0x84(%rsp)
  11798d:	movzbl (%rax,%rcx,1),%esi
  117991:	cmp    $0x20,%sil
  117995:	je     1179a1 <get_c_indent@@Base+0x11f1>
  117997:	cmp    $0x9,%sil
  11799b:	jne    1186d3 <get_c_indent@@Base+0x1f23>
  1179a1:	add    $0x2,%edx
  1179a4:	sub    $0x1,%rax
  1179a8:	movslq %edx,%rdx
  1179ab:	mov    %edx,0x84(%rsp)
  1179b2:	movzbl 0x1(%rax,%rdx,1),%esi
  1179b7:	mov    %edx,%ecx
  1179b9:	add    $0x1,%rdx
  1179bd:	cmp    $0x20,%sil
  1179c1:	je     1179ab <get_c_indent@@Base+0x11fb>
  1179c3:	cmp    $0x9,%sil
  1179c7:	je     1179ab <get_c_indent@@Base+0x11fb>
  1179c9:	test   %sil,%sil
  1179cc:	je     117a20 <get_c_indent@@Base+0x1270>
  1179ce:	mov    %ecx,0xb8(%rsp)
  1179d5:	jmpq   1172bb <get_c_indent@@Base+0xb0b>
  1179da:	mov    0x20(%rsp),%r14
  1179df:	mov    (%r14),%rdi
  1179e2:	callq  1007a0 <ml_get@@Base>
  1179e7:	mov    %rax,%rbx
  1179ea:	movslq 0x8(%r14),%rax
  1179ee:	lea    0x2(%rbx,%rax,1),%rdi
  1179f3:	mov    %rdi,0x90(%rsp)
  1179fb:	cmpb   $0x0,(%rdi)
  1179fe:	je     11755a <get_c_indent@@Base+0xdaa>
  117a04:	callq  607e0 <skipwhite@@Base>
  117a09:	mov    0x20(%rsp),%rsi
  117a0e:	sub    %rbx,%rax
  117a11:	mov    %eax,0x8(%rsi)
  117a14:	jmpq   11755a <get_c_indent@@Base+0xdaa>
  117a19:	nopl   0x0(%rax)
  117a20:	mov    %edi,0xb8(%rsp)
  117a27:	mov    %edi,%ecx
  117a29:	jmpq   1172bb <get_c_indent@@Base+0xb0b>
  117a2e:	mov    $0x1,%r9d
  117a34:	movzbl -0x1(%rax,%r9,1),%edi
  117a3a:	xor    %r14d,%r14d
  117a3d:	callq  5f070 <vim_isIDc@@Base>
  117a42:	test   %eax,%eax
  117a44:	sete   %r14b
  117a48:	jmpq   1174d6 <get_c_indent@@Base+0xd26>
  117a4d:	mov    0x396cbc(%rip),%rax        # 4ae710 <curwin@@Base>
  117a54:	mov    0x48(%rsp),%r13
  117a59:	mov    0x38(%rax),%rdi
  117a5d:	sub    $0x1,%rdi
  117a61:	callq  10ef90 <get_indent_lnum@@Base>
  117a66:	mov    %eax,(%rsp)
  117a69:	jmpq   116f72 <get_c_indent@@Base+0x7c2>
  117a6e:	mov    0x396c9b(%rip),%rax        # 4ae710 <curwin@@Base>
  117a75:	mov    0x48(%rsp),%r13
  117a7a:	mov    0x38(%rax),%rdi
  117a7e:	sub    $0x1,%rdi
  117a82:	callq  10ef90 <get_indent_lnum@@Base>
  117a87:	mov    %eax,(%rsp)
  117a8a:	jmpq   116f5b <get_c_indent@@Base+0x7ab>
  117a8f:	lea    0x11a214(%rip),%rsi        # 231caa <_IO_stdin_used@@Base+0x1b6ea>
  117a96:	xor    %edx,%edx
  117a98:	mov    %rax,%rdi
  117a9b:	callq  10dd90 <smsg_attr@@Base+0x2f0>
  117aa0:	test   %eax,%eax
  117aa2:	mov    0x3962cf(%rip),%r8        # 4add78 <curbuf@@Base>
  117aa9:	je     11729a <get_c_indent@@Base+0xaea>
  117aaf:	mov    0xb8(%rsp),%edi
  117ab6:	movl   $0x0,0x84(%rsp)
  117ac1:	test   %edi,%edi
  117ac3:	jle    1186a7 <get_c_indent@@Base+0x1ef7>
  117ac9:	mov    0x88(%rsp),%rsi
  117ad1:	xor    %eax,%eax
  117ad3:	mov    $0x1,%edx
  117ad8:	jmp    117b0a <get_c_indent@@Base+0x135a>
  117ada:	nopw   0x0(%rax,%rax,1)
  117ae0:	cmp    $0x7b,%cl
  117ae3:	je     117b19 <get_c_indent@@Base+0x1369>
  117ae5:	cmp    $0x7d,%cl
  117ae8:	jne    117af4 <get_c_indent@@Base+0x1344>
  117aea:	xor    %ecx,%ecx
  117aec:	cmp    $0x1,%edx
  117aef:	setne  %cl
  117af2:	sub    %ecx,%edx
  117af4:	add    $0x1,%eax
  117af7:	add    $0x1,%rsi
  117afb:	cmp    %edi,%eax
  117afd:	mov    %eax,0x84(%rsp)
  117b04:	je     1186ac <get_c_indent@@Base+0x1efc>
  117b0a:	movzbl (%rsi),%ecx
  117b0d:	cmp    $0x29,%cl
  117b10:	je     117aea <get_c_indent@@Base+0x133a>
  117b12:	ja     117ae0 <get_c_indent@@Base+0x1330>
  117b14:	cmp    $0x28,%cl
  117b17:	jne    117af4 <get_c_indent@@Base+0x1344>
  117b19:	add    $0x1,%edx
  117b1c:	jmp    117af4 <get_c_indent@@Base+0x1344>
  117b1e:	mov    %r12,%rdi
  117b21:	callq  10df60 <smsg_attr@@Base+0x4c0>
  117b26:	test   %eax,%eax
  117b28:	mov    $0x1,%edi
  117b2d:	je     1183bc <get_c_indent@@Base+0x1c0c>
  117b33:	mov    0x396bd6(%rip),%rax        # 4ae710 <curwin@@Base>
  117b3a:	mov    0x30(%rsp),%rsi
  117b3f:	mov    %r13,0x38(%rax)
  117b43:	callq  50479 <_init@@Base+0x1889>
  117b48:	cmp    $0x1,%eax
  117b4b:	je     1183a8 <get_c_indent@@Base+0x1bf8>
  117b51:	cmpl   $0x1,0x44(%rsp)
  117b56:	mov    0x39621b(%rip),%rax        # 4add78 <curbuf@@Base>
  117b5d:	je     118395 <get_c_indent@@Base+0x1be5>
  117b63:	cmpl   $0x3,0x44(%rsp)
  117b68:	je     11834c <get_c_indent@@Base+0x1b9c>
  117b6e:	sub    0x1610(%rax),%ebx
  117b74:	mov    $0x0,%eax
  117b79:	movl   $0x0,0x58(%rsp)
  117b81:	cmovs  %eax,%ebx
  117b84:	xor    %esi,%esi
  117b86:	mov    %r12,%rdi
  117b89:	callq  1162c0 <cin_iscase@@Base>
  117b8e:	test   %eax,%eax
  117b90:	mov    %eax,0x40(%rsp)
  117b94:	jne    1183ed <get_c_indent@@Base+0x1c3d>
  117b9a:	mov    %r12,%rdi
  117b9d:	callq  1164e0 <cin_isscopedecl@@Base>
  117ba2:	mov    %eax,%r14d
  117ba5:	mov    0x3961cc(%rip),%rax        # 4add78 <curbuf@@Base>
  117bac:	test   %r14d,%r14d
  117baf:	jne    1183d9 <get_c_indent@@Base+0x1c29>
  117bb5:	mov    0x1628(%rax),%esi
  117bbb:	test   %esi,%esi
  117bbd:	mov    %esi,0x40(%rsp)
  117bc1:	jne    11911c <get_c_indent@@Base+0x296c>
  117bc7:	add    0x1600(%rax),%ebx
  117bcd:	mov    %ebx,(%rsp)
  117bd0:	mov    0x396b39(%rip),%rdx        # 4ae710 <curwin@@Base>
  117bd7:	mov    0x14(%rsp),%eax
  117bdb:	lea    0x88(%rsp),%rsi
  117be3:	xor    %edi,%edi
  117be5:	mov    %r15d,0x28(%rsp)
  117bea:	mov    %r13,%rcx
  117bed:	mov    %rsi,0x50(%rsp)
  117bf2:	lea    0xc0(%rsp),%rsi
  117bfa:	movl   $0x0,0x6c(%rsp)
  117c02:	mov    %eax,0x40(%rdx)
  117c05:	mov    0x38(%rsp),%eax
  117c09:	mov    %edi,%r15d
  117c0c:	mov    %r13,0x38(%rdx)
  117c10:	movl   $0x0,0x3c(%rsp)
  117c18:	mov    %rsi,0x70(%rsp)
  117c1d:	mov    %r13,0x20(%rsp)
  117c22:	mov    %eax,0x44(%rdx)
  117c25:	mov    (%rsp),%eax
  117c28:	mov    %eax,0x60(%rsp)
  117c2c:	mov    %eax,%ebx
  117c2e:	sub    $0x1,%rcx
  117c32:	cmp    %rcx,0x30(%rsp)
  117c37:	movl   $0x0,0x40(%rdx)
  117c3e:	mov    %rcx,0x38(%rdx)
  117c42:	jl     117ce1 <get_c_indent@@Base+0x1531>
  117c48:	cmp    $0xa,%r14d
  117c4c:	je     117d30 <get_c_indent@@Base+0x1580>
  117c52:	cmp    $0x6,%r14d
  117c56:	je     11815c <get_c_indent@@Base+0x19ac>
  117c5c:	lea    -0x5(%r14),%eax
  117c60:	and    $0xfffffffb,%eax
  117c63:	je     117c7a <get_c_indent@@Base+0x14ca>
  117c65:	cmp    $0xc,%r14d
  117c69:	je     117c7a <get_c_indent@@Base+0x14ca>
  117c6b:	cmpb   $0x7b,(%r12)
  117c70:	mov    0x60(%rsp),%ebx
  117c74:	je     118050 <get_c_indent@@Base+0x18a0>
  117c7a:	mov    0x58(%rsp),%eax
  117c7e:	test   %eax,%eax
  117c80:	je     1184fb <get_c_indent@@Base+0x1d4b>
  117c86:	cmp    %rcx,0x30(%rsp)
  117c8b:	je     117c2e <get_c_indent@@Base+0x147e>
  117c8d:	test   %rcx,%rcx
  117c90:	je     1184fb <get_c_indent@@Base+0x1d4b>
  117c96:	mov    0x30(%rsp),%rax
  117c9b:	sub    $0x14,%rax
  117c9f:	cmp    %rax,%rcx
  117ca2:	jl     1184fb <get_c_indent@@Base+0x1d4b>
  117ca8:	callq  1007e0 <ml_get_curline@@Base>
  117cad:	mov    %rax,0x88(%rsp)
  117cb5:	callq  114080 <find_start_comment@@Base+0xa0>
  117cba:	test   %rax,%rax
  117cbd:	je     117e80 <get_c_indent@@Base+0x16d0>
  117cc3:	mov    (%rax),%rcx
  117cc6:	mov    0x396a43(%rip),%rdx        # 4ae710 <curwin@@Base>
  117ccd:	add    $0x1,%rcx
  117cd1:	movl   $0x0,0x40(%rdx)
  117cd8:	mov    %rcx,0x38(%rdx)
  117cdc:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  117ce1:	callq  114080 <find_start_comment@@Base+0xa0>
  117ce6:	test   %rax,%rax
  117ce9:	jne    117cc3 <get_c_indent@@Base+0x1513>
  117ceb:	callq  1007e0 <ml_get_curline@@Base>
  117cf0:	xor    %esi,%esi
  117cf2:	mov    %rax,%rdi
  117cf5:	mov    %rax,0x88(%rsp)
  117cfd:	callq  1162c0 <cin_iscase@@Base>
  117d02:	test   %eax,%eax
  117d04:	mov    %eax,%r13d
  117d07:	je     11854a <get_c_indent@@Base+0x1d9a>
  117d0d:	cmp    $0x9,%r14d
  117d11:	je     117ec8 <get_c_indent@@Base+0x1718>
  117d17:	test   %r15d,%r15d
  117d1a:	je     118189 <get_c_indent@@Base+0x19d9>
  117d20:	mov    0x3969e9(%rip),%rdx        # 4ae710 <curwin@@Base>
  117d27:	mov    0x38(%rdx),%rcx
  117d2b:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  117d30:	test   %rcx,%rcx
  117d33:	je     118691 <get_c_indent@@Base+0x1ee1>
  117d39:	mov    0x396038(%rip),%rax        # 4add78 <curbuf@@Base>
  117d40:	mov    0x30(%rsp),%rdi
  117d45:	movslq 0x1664(%rax),%rsi
  117d4c:	sub    %rsi,%rdi
  117d4f:	cmp    %rdi,%rcx
  117d52:	jl     11866b <get_c_indent@@Base+0x1ebb>
  117d58:	callq  1007e0 <ml_get_curline@@Base>
  117d5d:	mov    %rax,0x88(%rsp)
  117d65:	callq  114080 <find_start_comment@@Base+0xa0>
  117d6a:	test   %rax,%rax
  117d6d:	jne    117cc3 <get_c_indent@@Base+0x1513>
  117d73:	mov    0x396996(%rip),%rax        # 4ae710 <curwin@@Base>
  117d7a:	mov    0x50(%rsp),%rdi
  117d7f:	lea    0x38(%rax),%rsi
  117d83:	callq  10dc40 <smsg_attr@@Base+0x1a0>
  117d88:	test   %eax,%eax
  117d8a:	jne    117d20 <get_c_indent@@Base+0x1570>
  117d8c:	mov    0x88(%rsp),%rdi
  117d94:	callq  10db80 <smsg_attr@@Base+0xe0>
  117d99:	cmpb   $0x0,(%rax)
  117d9c:	je     117d20 <get_c_indent@@Base+0x1570>
  117d9e:	mov    0x88(%rsp),%rdi
  117da6:	xor    %esi,%esi
  117da8:	mov    $0x1,%edx
  117dad:	callq  10e2c0 <smsg_attr@@Base+0x820>
  117db2:	cmpl   $0x1,0x44(%rsp)
  117db7:	mov    %eax,(%rsp)
  117dba:	je     11863d <get_c_indent@@Base+0x1e8d>
  117dc0:	cmpb   $0x2c,(%rsp)
  117dc4:	je     117ec8 <get_c_indent@@Base+0x1718>
  117dca:	cmpb   $0x3b,(%rsp)
  117dce:	je     1184a4 <get_c_indent@@Base+0x1cf4>
  117dd4:	callq  1007e0 <ml_get_curline@@Base>
  117dd9:	mov    %rax,%rdi
  117ddc:	callq  10db80 <smsg_attr@@Base+0xe0>
  117de1:	lea    0x10e57e(%rip),%rsi        # 226366 <_IO_stdin_used@@Base+0xfda6>
  117de8:	mov    %rax,%rdi
  117deb:	mov    %rax,%r13
  117dee:	callq  10dfc0 <smsg_attr@@Base+0x520>
  117df3:	test   %eax,%eax
  117df5:	je     117e03 <get_c_indent@@Base+0x1653>
  117df7:	lea    0x7(%r13),%rdi
  117dfb:	callq  10db80 <smsg_attr@@Base+0xe0>
  117e00:	mov    %rax,%r13
  117e03:	mov    %ebp,0x68(%rsp)
  117e07:	mov    %ebx,0x48(%rsp)
  117e0b:	mov    %r13,%rbp
  117e0e:	mov    %r12,%r13
  117e11:	lea    0x366b88(%rip),%r12        # 47e9a0 <_IO_stdin_used@@Base+0x2683e0>
  117e18:	mov    $0x6,%eax
  117e1d:	lea    0x11b9cb(%rip),%rsi        # 2337ef <_IO_stdin_used@@Base+0x1d22f>
  117e24:	jmp    117e5a <get_c_indent@@Base+0x16aa>
  117e26:	nopw   %cs:0x0(%rax,%rax,1)
  117e30:	lea    0x366b89(%rip),%rax        # 47e9c0 <_IO_stdin_used@@Base+0x268400>
  117e37:	add    $0x8,%r12
  117e3b:	cmp    %r12,%rax
  117e3e:	je     118410 <get_c_indent@@Base+0x1c60>
  117e44:	mov    (%r12),%rsi
  117e48:	mov    %rsi,%rdi
  117e4b:	mov    %rsi,0x78(%rsp)
  117e50:	callq  4ed80 <_init@@Base+0x190>
  117e55:	mov    0x78(%rsp),%rsi
  117e5a:	mov    %rbp,%rdi
  117e5d:	movslq %eax,%rbx
  117e60:	callq  10dfc0 <smsg_attr@@Base+0x520>
  117e65:	test   %eax,%eax
  117e67:	je     117e30 <get_c_indent@@Base+0x1680>
  117e69:	lea    0x0(%rbp,%rbx,1),%rdi
  117e6e:	callq  10db80 <smsg_attr@@Base+0xe0>
  117e73:	mov    %rax,%rbp
  117e76:	jmp    117e11 <get_c_indent@@Base+0x1661>
  117e78:	nopl   0x0(%rax,%rax,1)
  117e80:	mov    0x396889(%rip),%rax        # 4ae710 <curwin@@Base>
  117e87:	mov    0x50(%rsp),%rdi
  117e8c:	lea    0x38(%rax),%rsi
  117e90:	callq  10dc40 <smsg_attr@@Base+0x1a0>
  117e95:	test   %eax,%eax
  117e97:	jne    117d20 <get_c_indent@@Base+0x1570>
  117e9d:	mov    0x88(%rsp),%rdi
  117ea5:	callq  4fccd <_init@@Base+0x10dd>
  117eaa:	test   %eax,%eax
  117eac:	jne    118519 <get_c_indent@@Base+0x1d69>
  117eb2:	mov    0x88(%rsp),%rdi
  117eba:	callq  10db80 <smsg_attr@@Base+0xe0>
  117ebf:	cmpb   $0x0,(%rax)
  117ec2:	je     117d20 <get_c_indent@@Base+0x1570>
  117ec8:	mov    0x20(%rsp),%r13
  117ecd:	mov    0x28(%rsp),%r15d
  117ed2:	mov    %ebx,(%rsp)
  117ed5:	movzbl (%r12),%ecx
  117eda:	mov    0x395e97(%rip),%rax        # 4add78 <curbuf@@Base>
  117ee1:	mov    0x396828(%rip),%rdx        # 4ae710 <curwin@@Base>
  117ee8:	jmpq   11777e <get_c_indent@@Base+0xfce>
  117eed:	nopl   (%rax)
  117ef0:	mov    0x98(%rsp),%rdi
  117ef8:	lea    0x88(%rsp),%rsi
  117f00:	callq  116700 <cin_islabel@@Base+0x190>
  117f05:	movl   $0x3,0x44(%rsp)
  117f0d:	mov    %eax,%ebx
  117f0f:	jmpq   116c6c <get_c_indent@@Base+0x4bc>
  117f14:	callq  1007e0 <ml_get_curline@@Base>
  117f19:	mov    %rax,%rdi
  117f1c:	callq  607e0 <skipwhite@@Base>
  117f21:	xor    %esi,%esi
  117f23:	mov    %rax,%rdi
  117f26:	callq  1162c0 <cin_iscase@@Base>
  117f2b:	test   %eax,%eax
  117f2d:	jne    1180f6 <get_c_indent@@Base+0x1946>
  117f33:	mov    0x395e3e(%rip),%rax        # 4add78 <curbuf@@Base>
  117f3a:	jmpq   116c47 <get_c_indent@@Base+0x497>
  117f3f:	mov    0x395e32(%rip),%rax        # 4add78 <curbuf@@Base>
  117f46:	mov    $0x28,%edi
  117f4b:	mov    0x1664(%rax),%esi
  117f51:	callq  114130 <find_start_comment@@Base+0x150>
  117f56:	test   %rax,%rax
  117f59:	je     116c32 <get_c_indent@@Base+0x482>
  117f5f:	mov    (%rax),%rax
  117f62:	mov    %rax,0x98(%rsp)
  117f6a:	jmpq   116c32 <get_c_indent@@Base+0x482>
  117f6f:	nop
  117f70:	mov    0x396799(%rip),%rdi        # 4ae710 <curwin@@Base>
  117f77:	lea    0x84(%rsp),%rdx
  117f7f:	lea    0xa0(%rsp),%rsi
  117f87:	xor    %r8d,%r8d
  117f8a:	xor    %ecx,%ecx
  117f8c:	callq  60170 <getvcol@@Base>
  117f91:	xor    %eax,%eax
  117f93:	cmpb   $0x7b,0x0(%rbp)
  117f97:	mov    0x84(%rsp),%ebx
  117f9e:	setne  %al
  117fa1:	add    $0x1,%eax
  117fa4:	mov    %eax,0x44(%rsp)
  117fa8:	jmpq   116c6c <get_c_indent@@Base+0x4bc>
  117fad:	mov    0x39675c(%rip),%rax        # 4ae710 <curwin@@Base>
  117fb4:	mov    0xb0(%rsp),%rdx
  117fbc:	mov    0x38(%rax),%r8
  117fc0:	mov    %rdx,0x38(%rax)
  117fc4:	mov    %r8,0x20(%rsp)
  117fc9:	callq  1007e0 <ml_get_curline@@Base>
  117fce:	mov    0x90(%rsp),%rsi
  117fd6:	xor    %edi,%edi
  117fd8:	sub    %rax,%rsi
  117fdb:	mov    0x39672e(%rip),%rax        # 4ae710 <curwin@@Base>
  117fe2:	lea    0x1(%rsi),%edx
  117fe5:	mov    %rsi,0x18(%rsp)
  117fea:	mov    $0x29,%esi
  117fef:	mov    %edx,0x40(%rax)
  117ff2:	mov    0x395d7f(%rip),%rax        # 4add78 <curbuf@@Base>
  117ff9:	xor    %edx,%edx
  117ffb:	mov    0x1664(%rax),%ecx
  118001:	callq  1950d0 <findmatchlimit@@Base>
  118006:	test   %rax,%rax
  118009:	mov    0xb0(%rsp),%rdi
  118011:	mov    0x20(%rsp),%r8
  118016:	je     11802b <get_c_indent@@Base+0x187b>
  118018:	mov    (%rax),%rdi
  11801b:	mov    0xb0(%rsp),%rdx
  118023:	cmp    %rdx,%rdi
  118026:	je     118068 <get_c_indent@@Base+0x18b8>
  118028:	mov    %rdx,%rdi
  11802b:	mov    0x3966de(%rip),%rax        # 4ae710 <curwin@@Base>
  118032:	mov    %r8,0x38(%rax)
  118036:	callq  1007a0 <ml_get@@Base>
  11803b:	movslq 0x18(%rsp),%rdx
  118040:	add    %rdx,%rax
  118043:	mov    %rax,0x90(%rsp)
  11804b:	jmpq   117228 <get_c_indent@@Base+0xa78>
  118050:	mov    0x395d21(%rip),%rax        # 4add78 <curbuf@@Base>
  118057:	mov    0x1610(%rax),%eax
  11805d:	mov    %eax,0x6c(%rsp)
  118061:	add    %eax,%ebx
  118063:	jmpq   117c7a <get_c_indent@@Base+0x14ca>
  118068:	mov    0x8(%rax),%eax
  11806b:	cmp    0xb8(%rsp),%eax
  118072:	lea    0x1(%rax),%edx
  118075:	cmovl  %edx,%ebp
  118078:	jmp    11802b <get_c_indent@@Base+0x187b>
  11807a:	mov    0xd0(%rsp),%edi
  118081:	callq  50121 <_init@@Base+0x1531>
  118086:	mov    %eax,(%rsp)
  118089:	cmpb   $0x2f,(%r12)
  11808e:	je     118135 <get_c_indent@@Base+0x1985>
  118094:	cmp    $0x1,%r13
  118098:	jle    116f72 <get_c_indent@@Base+0x7c2>
  11809e:	lea    -0x1(%r13),%rbx
  1180a2:	mov    %rbx,%rdi
  1180a5:	callq  1007a0 <ml_get@@Base>
  1180aa:	mov    %rax,0x88(%rsp)
  1180b2:	cmpb   $0x0,(%rax)
  1180b5:	mov    %rax,%rbp
  1180b8:	je     116f72 <get_c_indent@@Base+0x7c2>
  1180be:	mov    %rax,%rdi
  1180c1:	callq  4ed80 <_init@@Base+0x190>
  1180c6:	cmpb   $0x5c,-0x1(%rbp,%rax,1)
  1180cb:	jne    116f72 <get_c_indent@@Base+0x7c2>
  1180d1:	mov    %rbx,%rdi
  1180d4:	callq  4fad9 <_init@@Base+0xee9>
  1180d9:	cmp    $0x0,%eax
  1180dc:	mov    %eax,%ebx
  1180de:	jg     1173c9 <get_c_indent@@Base+0xc19>
  1180e4:	jne    116f72 <get_c_indent@@Base+0x7c2>
  1180ea:	mov    0x18(%rsp),%esi
  1180ee:	add    %esi,(%rsp)
  1180f1:	jmpq   116f72 <get_c_indent@@Base+0x7c2>
  1180f6:	callq  10e890 <get_indent@@Base>
  1180fb:	movl   $0x3,0x44(%rsp)
  118103:	mov    %eax,%ebx
  118105:	jmpq   116c6c <get_c_indent@@Base+0x4bc>
  11810a:	test   %r14d,%r14d
  11810d:	je     117818 <get_c_indent@@Base+0x1068>
  118113:	mov    0x395c5e(%rip),%rax        # 4add78 <curbuf@@Base>
  11811a:	add    0x1688(%rax),%ebx
  118120:	jmpq   117719 <get_c_indent@@Base+0xf69>
  118125:	callq  4ed90 <_init@@Base+0x1a0>
  11812a:	mov    0x8(%rax),%eax
  11812d:	cmp    %eax,0x8(%rbp)
  118130:	jmpq   117701 <get_c_indent@@Base+0xf51>
  118135:	movzbl 0x1(%r12),%eax
  11813b:	cmp    $0x2a,%al
  11813d:	je     118147 <get_c_indent@@Base+0x1997>
  11813f:	cmp    $0x2f,%al
  118141:	jne    118094 <get_c_indent@@Base+0x18e4>
  118147:	mov    0x395c2a(%rip),%rax        # 4add78 <curbuf@@Base>
  11814e:	mov    0x1634(%rax),%eax
  118154:	add    %eax,(%rsp)
  118157:	jmpq   118094 <get_c_indent@@Base+0x18e4>
  11815c:	mov    0x3c(%rsp),%esi
  118160:	mov    %ebx,(%rsp)
  118163:	mov    0x20(%rsp),%r13
  118168:	mov    0x28(%rsp),%r15d
  11816d:	test   %esi,%esi
  11816f:	jle    118291 <get_c_indent@@Base+0x1ae1>
  118175:	movzbl (%r12),%ecx
  11817a:	mov    0x395bf7(%rip),%rax        # 4add78 <curbuf@@Base>
  118181:	mov    %esi,(%rsp)
  118184:	jmpq   11777e <get_c_indent@@Base+0xfce>
  118189:	lea    -0x6(%r14),%eax
  11818d:	and    $0xfffffffb,%eax
  118190:	je     1184a4 <get_c_indent@@Base+0x1cf4>
  118196:	movzbl 0x40(%rsp),%eax
  11819b:	cmp    $0x3,%r14d
  11819f:	sete   %dl
  1181a2:	and    $0x1,%eax
  1181a5:	or     %al,%dl
  1181a7:	je     1181ae <get_c_indent@@Base+0x19fe>
  1181a9:	test   %r13d,%r13d
  1181ac:	jne    1181b9 <get_c_indent@@Base+0x1a09>
  1181ae:	test   %r13d,%r13d
  1181b1:	jne    1181fb <get_c_indent@@Base+0x1a4b>
  1181b3:	cmp    $0x7,%r14d
  1181b7:	jne    1181fb <get_c_indent@@Base+0x1a4b>
  1181b9:	callq  114240 <find_start_comment@@Base+0x260>
  1181be:	test   %rax,%rax
  1181c1:	je     1181d1 <get_c_indent@@Base+0x1a21>
  1181c3:	mov    0x30(%rsp),%rsi
  1181c8:	cmp    (%rax),%rsi
  1181cb:	jne    117d20 <get_c_indent@@Base+0x1570>
  1181d1:	mov    0x20(%rsp),%r13
  1181d6:	mov    0x28(%rsp),%r15d
  1181db:	callq  10e890 <get_indent@@Base>
  1181e0:	movzbl (%r12),%ecx
  1181e5:	mov    %eax,(%rsp)
  1181e8:	mov    0x396521(%rip),%rdx        # 4ae710 <curwin@@Base>
  1181ef:	mov    0x395b82(%rip),%rax        # 4add78 <curbuf@@Base>
  1181f6:	jmpq   11777e <get_c_indent@@Base+0xfce>
  1181fb:	mov    0x39650e(%rip),%rax        # 4ae710 <curwin@@Base>
  118202:	mov    0x38(%rax),%rdi
  118206:	callq  116460 <cin_iscase@@Base+0x1a0>
  11820b:	cmp    $0x5,%r14d
  11820f:	je     11830d <get_c_indent@@Base+0x1b5d>
  118215:	test   %eax,%eax
  118217:	je     1182c3 <get_c_indent@@Base+0x1b13>
  11821d:	mov    0x20(%rsp),%r13
  118222:	mov    0x28(%rsp),%r15d
  118227:	mov    %eax,%esi
  118229:	mov    %esi,(%rsp)
  11822c:	callq  1007e0 <ml_get_curline@@Base>
  118231:	mov    %rax,%rdi
  118234:	callq  1163b0 <cin_iscase@@Base+0xf0>
  118239:	test   %rax,%rax
  11823c:	mov    %rax,0x88(%rsp)
  118244:	mov    (%rsp),%esi
  118247:	je     117ed5 <get_c_indent@@Base+0x1725>
  11824d:	mov    %rax,%rdi
  118250:	mov    %esi,(%rsp)
  118253:	callq  10de60 <smsg_attr@@Base+0x3c0>
  118258:	test   %eax,%eax
  11825a:	movzbl (%r12),%ecx
  11825f:	mov    (%rsp),%esi
  118262:	je     117eda <get_c_indent@@Base+0x172a>
  118268:	cmp    $0x7b,%cl
  11826b:	mov    0x395b06(%rip),%rax        # 4add78 <curbuf@@Base>
  118272:	je     1182a9 <get_c_indent@@Base+0x1af9>
  118274:	mov    0x1608(%rax),%edx
  11827a:	add    0x1600(%rax),%edx
  118280:	add    %edx,%esi
  118282:	mov    0x396487(%rip),%rdx        # 4ae710 <curwin@@Base>
  118289:	mov    %esi,(%rsp)
  11828c:	jmpq   11777e <get_c_indent@@Base+0xfce>
  118291:	mov    0x18(%rsp),%esi
  118295:	movzbl (%r12),%ecx
  11829a:	add    %esi,(%rsp)
  11829d:	mov    0x395ad4(%rip),%rax        # 4add78 <curbuf@@Base>
  1182a4:	jmpq   11777e <get_c_indent@@Base+0xfce>
  1182a9:	add    0x1610(%rax),%esi
  1182af:	mov    %esi,(%rsp)
  1182b2:	jmpq   116ca2 <get_c_indent@@Base+0x4f2>
  1182b7:	mov    0x40(%rsp),%edx
  1182bb:	test   %edx,%edx
  1182bd:	je     117ec8 <get_c_indent@@Base+0x1718>
  1182c3:	callq  10e890 <get_indent@@Base>
  1182c8:	test   %r13d,%r13d
  1182cb:	mov    0x395aa6(%rip),%rdx        # 4add78 <curbuf@@Base>
  1182d2:	je     118344 <get_c_indent@@Base+0x1b94>
  1182d4:	mov    0x1624(%rdx),%ecx
  1182da:	add    %ecx,%eax
  1182dc:	mov    $0x8,%r14d
  1182e2:	mov    %eax,0x60(%rsp)
  1182e6:	mov    0x1628(%rdx),%eax
  1182ec:	mov    0x39641d(%rip),%rdx        # 4ae710 <curwin@@Base>
  1182f3:	test   %eax,%eax
  1182f5:	mov    0x38(%rdx),%rcx
  1182f9:	jne    117c2e <get_c_indent@@Base+0x147e>
  1182ff:	xor    %r15d,%r15d
  118302:	mov    $0x4,%r14d
  118308:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  11830d:	test   %eax,%eax
  11830f:	je     1182b7 <get_c_indent@@Base+0x1b07>
  118311:	mov    %eax,%esi
  118313:	mov    0x40(%rsp),%eax
  118317:	mov    0x20(%rsp),%r13
  11831c:	mov    0x28(%rsp),%r15d
  118321:	test   %eax,%eax
  118323:	jne    118229 <get_c_indent@@Base+0x1a79>
  118329:	movzbl (%r12),%ecx
  11832e:	mov    0x395a43(%rip),%rax        # 4add78 <curbuf@@Base>
  118335:	mov    0x3963d4(%rip),%rdx        # 4ae710 <curwin@@Base>
  11833c:	mov    %esi,(%rsp)
  11833f:	jmpq   11777e <get_c_indent@@Base+0xfce>
  118344:	mov    0x1670(%rdx),%ecx
  11834a:	jmp    1182da <get_c_indent@@Base+0x1b2a>
  11834c:	add    0x1604(%rax),%ebx
  118352:	callq  1007e0 <ml_get_curline@@Base>
  118357:	mov    %rax,%rdi
  11835a:	callq  607e0 <skipwhite@@Base>
  11835f:	mov    %rax,%rdi
  118362:	mov    %rax,0x88(%rsp)
  11836a:	callq  4fccd <_init@@Base+0x10dd>
  11836f:	test   %eax,%eax
  118371:	mov    %eax,0x58(%rsp)
  118375:	je     117b84 <get_c_indent@@Base+0x13d4>
  11837b:	mov    0x3959f6(%rip),%rax        # 4add78 <curbuf@@Base>
  118382:	movl   $0x0,0x58(%rsp)
  11838a:	add    0x1684(%rax),%ebx
  118390:	jmpq   117b84 <get_c_indent@@Base+0x13d4>
  118395:	mov    0x1618(%rax),%ebx
  11839b:	movl   $0x1,0x58(%rsp)
  1183a3:	jmpq   117b84 <get_c_indent@@Base+0x13d4>
  1183a8:	callq  10e890 <get_indent@@Base>
  1183ad:	mov    0x39635c(%rip),%rdx        # 4ae710 <curwin@@Base>
  1183b4:	mov    %eax,(%rsp)
  1183b7:	jmpq   117129 <get_c_indent@@Base+0x979>
  1183bc:	mov    %r13,%rsi
  1183bf:	mov    %r12,%rdi
  1183c2:	callq  5002c <_init@@Base+0x143c>
  1183c7:	test   %eax,%eax
  1183c9:	je     117b51 <get_c_indent@@Base+0x13a1>
  1183cf:	mov    $0x2,%edi
  1183d4:	jmpq   117b33 <get_c_indent@@Base+0x1383>
  1183d9:	add    0x166c(%rax),%ebx
  1183df:	mov    $0x7,%r14d
  1183e5:	mov    %ebx,(%rsp)
  1183e8:	jmpq   117bd0 <get_c_indent@@Base+0x1420>
  1183ed:	mov    0x395984(%rip),%rax        # 4add78 <curbuf@@Base>
  1183f4:	movl   $0x0,0x40(%rsp)
  1183fc:	mov    $0x3,%r14d
  118402:	add    0x1620(%rax),%ebx
  118408:	mov    %ebx,(%rsp)
  11840b:	jmpq   117bd0 <get_c_indent@@Base+0x1420>
  118410:	test   %ebx,%ebx
  118412:	je     117e11 <get_c_indent@@Base+0x1661>
  118418:	mov    %r13,%r12
  11841b:	lea    0x10dea7(%rip),%rsi        # 2262c9 <_IO_stdin_used@@Base+0xfd09>
  118422:	mov    %rbp,%r13
  118425:	mov    %r13,%rdi
  118428:	mov    0x48(%rsp),%ebx
  11842c:	mov    0x68(%rsp),%ebp
  118430:	callq  10dfc0 <smsg_attr@@Base+0x520>
  118435:	test   %eax,%eax
  118437:	jne    117ec8 <get_c_indent@@Base+0x1718>
  11843d:	lea    0x11e352(%rip),%rdx        # 236796 <_IO_stdin_used@@Base+0x201d6>
  118444:	lea    0x11a0bc(%rip),%rsi        # 232507 <_IO_stdin_used@@Base+0x1bf47>
  11844b:	mov    %r13,%rdi
  11844e:	callq  10dd90 <smsg_attr@@Base+0x2f0>
  118453:	test   %eax,%eax
  118455:	jne    117ec8 <get_c_indent@@Base+0x1718>
  11845b:	mov    (%rsp),%eax
  11845e:	cmp    $0x7b,%al
  118460:	je     117d20 <get_c_indent@@Base+0x1570>
  118466:	test   %al,%al
  118468:	je     117d20 <get_c_indent@@Base+0x1570>
  11846e:	mov    0x88(%rsp),%rdi
  118476:	mov    $0x29,%edx
  11847b:	mov    $0x28,%esi
  118480:	callq  10e490 <smsg_attr@@Base+0x9f0>
  118485:	test   %eax,%eax
  118487:	jne    1184d9 <get_c_indent@@Base+0x1d29>
  118489:	mov    0x88(%rsp),%rdi
  118491:	mov    $0x7d,%edx
  118496:	mov    $0x7b,%esi
  11849b:	callq  10e490 <smsg_attr@@Base+0x9f0>
  1184a0:	test   %eax,%eax
  1184a2:	jne    1184c9 <get_c_indent@@Base+0x1d19>
  1184a4:	mov    0x3c(%rsp),%esi
  1184a8:	mov    %ebx,(%rsp)
  1184ab:	mov    0x20(%rsp),%r13
  1184b0:	mov    0x28(%rsp),%r15d
  1184b5:	test   %esi,%esi
  1184b7:	jg     118329 <get_c_indent@@Base+0x1b79>
  1184bd:	mov    0x18(%rsp),%esi
  1184c1:	add    %esi,(%rsp)
  1184c4:	jmpq   117ed5 <get_c_indent@@Base+0x1725>
  1184c9:	callq  114240 <find_start_comment@@Base+0x260>
  1184ce:	test   %rax,%rax
  1184d1:	jne    117cc3 <get_c_indent@@Base+0x1513>
  1184d7:	jmp    1184a4 <get_c_indent@@Base+0x1cf4>
  1184d9:	mov    0x395898(%rip),%rax        # 4add78 <curbuf@@Base>
  1184e0:	mov    $0x28,%edi
  1184e5:	mov    0x1664(%rax),%esi
  1184eb:	callq  114130 <find_start_comment@@Base+0x150>
  1184f0:	test   %rax,%rax
  1184f3:	jne    117cc3 <get_c_indent@@Base+0x1513>
  1184f9:	jmp    118489 <get_c_indent@@Base+0x1cd9>
  1184fb:	mov    %ebx,(%rsp)
  1184fe:	mov    0x20(%rsp),%r13
  118503:	mov    0x28(%rsp),%r15d
  118508:	movzbl (%r12),%ecx
  11850d:	mov    0x395864(%rip),%rax        # 4add78 <curbuf@@Base>
  118514:	jmpq   11777e <get_c_indent@@Base+0xfce>
  118519:	mov    0x395858(%rip),%rax        # 4add78 <curbuf@@Base>
  118520:	mov    0x20(%rsp),%r13
  118525:	mov    0x28(%rsp),%r15d
  11852a:	movzbl (%r12),%ecx
  11852f:	mov    0x1684(%rax),%edx
  118535:	add    %ebx,%edx
  118537:	sub    0x6c(%rsp),%edx
  11853b:	mov    %edx,(%rsp)
  11853e:	mov    0x3961cb(%rip),%rdx        # 4ae710 <curwin@@Base>
  118545:	jmpq   11777e <get_c_indent@@Base+0xfce>
  11854a:	mov    0x88(%rsp),%rdi
  118552:	callq  1164e0 <cin_isscopedecl@@Base>
  118557:	test   %eax,%eax
  118559:	jne    117d0d <get_c_indent@@Base+0x155d>
  11855f:	mov    %r14d,%eax
  118562:	and    $0xfffffffb,%eax
  118565:	cmp    $0x3,%eax
  118568:	je     11965d <get_c_indent@@Base+0x2ead>
  11856e:	mov    0x395803(%rip),%rax        # 4add78 <curbuf@@Base>
  118575:	mov    0x1678(%rax),%eax
  11857b:	test   %eax,%eax
  11857d:	je     1195a6 <get_c_indent@@Base+0x2df6>
  118583:	callq  1007e0 <ml_get_curline@@Base>
  118588:	mov    %rax,0x88(%rsp)
  118590:	mov    0x396179(%rip),%rax        # 4ae710 <curwin@@Base>
  118597:	mov    0x50(%rsp),%rdi
  11859c:	lea    0x38(%rax),%rsi
  1185a0:	callq  10dc40 <smsg_attr@@Base+0x1a0>
  1185a5:	test   %eax,%eax
  1185a7:	jne    117d20 <get_c_indent@@Base+0x1570>
  1185ad:	mov    0x88(%rsp),%rdi
  1185b5:	callq  10db80 <smsg_attr@@Base+0xe0>
  1185ba:	cmpb   $0x0,(%rax)
  1185bd:	je     117d20 <get_c_indent@@Base+0x1570>
  1185c3:	cmp    $0x5,%r14d
  1185c7:	je     1195e7 <get_c_indent@@Base+0x2e37>
  1185cd:	mov    0x3957a4(%rip),%rax        # 4add78 <curbuf@@Base>
  1185d4:	mov    0x1640(%rax),%r13d
  1185db:	test   %r13d,%r13d
  1185de:	jle    1189b7 <get_c_indent@@Base+0x2207>
  1185e4:	mov    0x70(%rsp),%rdi
  1185e9:	callq  505f2 <_init@@Base+0x1a02>
  1185ee:	mov    %eax,%r13d
  1185f1:	callq  1007e0 <ml_get_curline@@Base>
  1185f6:	test   %r13d,%r13d
  1185f9:	mov    %rax,%rdi
  1185fc:	mov    %rax,0x88(%rsp)
  118604:	je     1189bf <get_c_indent@@Base+0x220f>
  11860a:	cmp    $0x6,%r14d
  11860e:	je     1184a4 <get_c_indent@@Base+0x1cf4>
  118614:	cmpb   $0x7b,(%r12)
  118619:	jne    1190eb <get_c_indent@@Base+0x293b>
  11861f:	mov    0x3960ea(%rip),%rdx        # 4ae710 <curwin@@Base>
  118626:	movl   $0x0,0x18(%rsp)
  11862e:	mov    $0x6,%r14d
  118634:	mov    0x38(%rdx),%rcx
  118638:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  11863d:	mov    0x3960cc(%rip),%rax        # 4ae710 <curwin@@Base>
  118644:	mov    0x50(%rsp),%rdi
  118649:	xor    %edx,%edx
  11864b:	mov    0x38(%rax),%rsi
  11864f:	callq  50200 <_init@@Base+0x1610>
  118654:	test   %eax,%eax
  118656:	je     117dc0 <get_c_indent@@Base+0x1610>
  11865c:	cmpb   $0x3b,(%rsp)
  118660:	jne    11846e <get_c_indent@@Base+0x1cbe>
  118666:	jmpq   1184a4 <get_c_indent@@Base+0x1cf4>
  11866b:	mov    0x20(%rsp),%r13
  118670:	mov    0x28(%rsp),%r15d
  118675:	mov    %ebx,(%rsp)
  118678:	mov    0x3c(%rsp),%esi
  11867c:	test   %esi,%esi
  11867e:	jle    11913c <get_c_indent@@Base+0x298c>
  118684:	movzbl (%r12),%ecx
  118689:	mov    %esi,(%rsp)
  11868c:	jmpq   11777e <get_c_indent@@Base+0xfce>
  118691:	mov    %ebx,(%rsp)
  118694:	mov    0x20(%rsp),%r13
  118699:	mov    0x28(%rsp),%r15d
  11869e:	mov    0x3956d3(%rip),%rax        # 4add78 <curbuf@@Base>
  1186a5:	jmp    118678 <get_c_indent@@Base+0x1ec8>
  1186a7:	mov    $0x1,%edx
  1186ac:	mov    0x3956c5(%rip),%rax        # 4add78 <curbuf@@Base>
  1186b3:	movl   $0x0,0xb8(%rsp)
  1186be:	movl   $0x7fffffff,(%rsp)
  1186c5:	imul   0x1654(%rax),%edx
  1186cc:	add    %edx,%ebx
  1186ce:	jmpq   117303 <get_c_indent@@Base+0xb53>
  1186d3:	mov    %edi,%ecx
  1186d5:	jmpq   1179c9 <get_c_indent@@Base+0x1219>
  1186da:	mov    0x88(%rsp),%rdi
  1186e2:	callq  10db80 <smsg_attr@@Base+0xe0>
  1186e7:	cmpb   $0x0,(%rax)
  1186ea:	je     117925 <get_c_indent@@Base+0x1175>
  1186f0:	mov    0x88(%rsp),%rdi
  1186f8:	lea    0x10dc3e(%rip),%rsi        # 22633d <_IO_stdin_used@@Base+0xfd7d>
  1186ff:	xor    %edx,%edx
  118701:	callq  10dd90 <smsg_attr@@Base+0x2f0>
  118706:	test   %eax,%eax
  118708:	jne    11874a <get_c_indent@@Base+0x1f9a>
  11870a:	mov    0x88(%rsp),%rbx
  118712:	cmpb   $0x0,(%rbx)
  118715:	je     11872a <get_c_indent@@Base+0x1f7a>
  118717:	mov    %rbx,%rdi
  11871a:	callq  4ed80 <_init@@Base+0x190>
  11871f:	cmpb   $0x5c,-0x1(%rbx,%rax,1)
  118724:	je     1187c4 <get_c_indent@@Base+0x2014>
  11872a:	xor    %edx,%edx
  11872c:	xor    %edi,%edi
  11872e:	mov    %r13,%rsi
  118731:	callq  50200 <_init@@Base+0x1610>
  118736:	test   %eax,%eax
  118738:	je     11894c <get_c_indent@@Base+0x219c>
  11873e:	movl   $0x0,(%rsp)
  118745:	jmpq   118089 <get_c_indent@@Base+0x18d9>
  11874a:	mov    0x88(%rsp),%rdi
  118752:	mov    $0x29,%edx
  118757:	mov    $0x28,%esi
  11875c:	callq  10e490 <smsg_attr@@Base+0x9f0>
  118761:	test   %eax,%eax
  118763:	jne    1187fe <get_c_indent@@Base+0x204e>
  118769:	mov    0x395fa0(%rip),%rdx        # 4ae710 <curwin@@Base>
  118770:	mov    0x38(%rdx),%rax
  118774:	cmp    $0x1,%rax
  118778:	jle    1187da <get_c_indent@@Base+0x202a>
  11877a:	lea    -0x1(%rax),%rdi
  11877e:	callq  1007a0 <ml_get@@Base>
  118783:	mov    %rax,0x88(%rsp)
  11878b:	cmpb   $0x0,(%rax)
  11878e:	mov    %rax,%rbx
  118791:	je     1187da <get_c_indent@@Base+0x202a>
  118793:	mov    %rax,%rdi
  118796:	callq  4ed80 <_init@@Base+0x190>
  11879b:	cmpb   $0x5c,-0x1(%rbx,%rax,1)
  1187a0:	jne    1187da <get_c_indent@@Base+0x202a>
  1187a2:	mov    0x395f67(%rip),%rdx        # 4ae710 <curwin@@Base>
  1187a9:	mov    0x38(%rdx),%rax
  1187ad:	movl   $0x0,0x40(%rdx)
  1187b4:	sub    $0x1,%rax
  1187b8:	cmp    $0x1,%rax
  1187bc:	mov    %rax,0x38(%rdx)
  1187c0:	jg     11877a <get_c_indent@@Base+0x1fca>
  1187c2:	jmp    1187da <get_c_indent@@Base+0x202a>
  1187c4:	mov    $0x29,%edx
  1187c9:	mov    $0x28,%esi
  1187ce:	mov    %rbx,%rdi
  1187d1:	callq  10e490 <smsg_attr@@Base+0x9f0>
  1187d6:	test   %eax,%eax
  1187d8:	jne    11883e <get_c_indent@@Base+0x208e>
  1187da:	callq  10e890 <get_indent@@Base>
  1187df:	test   %eax,%eax
  1187e1:	mov    %eax,(%rsp)
  1187e4:	jne    118089 <get_c_indent@@Base+0x18d9>
  1187ea:	callq  4fd72 <_init@@Base+0x1182>
  1187ef:	test   %eax,%eax
  1187f1:	cmove  0x18(%rsp),%eax
  1187f6:	mov    %eax,(%rsp)
  1187f9:	jmpq   118089 <get_c_indent@@Base+0x18d9>
  1187fe:	mov    0x395573(%rip),%rax        # 4add78 <curbuf@@Base>
  118805:	mov    $0x28,%edi
  11880a:	mov    0x1664(%rax),%esi
  118810:	callq  114130 <find_start_comment@@Base+0x150>
  118815:	test   %rax,%rax
  118818:	je     118769 <get_c_indent@@Base+0x1fb9>
  11881e:	mov    0x395eeb(%rip),%rdx        # 4ae710 <curwin@@Base>
  118825:	mov    (%rax),%rsi
  118828:	test   %ebx,%ebx
  11882a:	mov    0x8(%rax),%rdi
  11882e:	mov    %rsi,0x38(%rdx)
  118832:	mov    %rdi,0x40(%rdx)
  118836:	je     118770 <get_c_indent@@Base+0x1fc0>
  11883c:	jmp    1187da <get_c_indent@@Base+0x202a>
  11883e:	mov    0x395533(%rip),%rax        # 4add78 <curbuf@@Base>
  118845:	mov    $0x28,%edi
  11884a:	mov    $0x5c,%ebx
  11884f:	mov    0x1664(%rax),%esi
  118855:	callq  114130 <find_start_comment@@Base+0x150>
  11885a:	test   %rax,%rax
  11885d:	jne    11881e <get_c_indent@@Base+0x206e>
  11885f:	jmpq   1187da <get_c_indent@@Base+0x202a>
  118864:	mov    0x39550d(%rip),%rax        # 4add78 <curbuf@@Base>
  11886b:	mov    0x395e9e(%rip),%rdx        # 4ae710 <curwin@@Base>
  118872:	mov    0x160c(%rax),%eax
  118878:	mov    %eax,(%rsp)
  11887b:	jmpq   117129 <get_c_indent@@Base+0x979>
  118880:	mov    0xb0(%rsp),%rdx
  118888:	movl   $0x7fffffff,(%rsp)
  11888f:	jmpq   1171df <get_c_indent@@Base+0xa2f>
  118894:	mov    %r12,%rdi
  118897:	callq  10db80 <smsg_attr@@Base+0xe0>
  11889c:	cmpb   $0x0,(%rax)
  11889f:	je     117853 <get_c_indent@@Base+0x10a3>
  1188a5:	mov    $0x7b,%esi
  1188aa:	mov    %r12,%rdi
  1188ad:	callq  11c810 <vim_strchr@@Base>
  1188b2:	test   %rax,%rax
  1188b5:	jne    117853 <get_c_indent@@Base+0x10a3>
  1188bb:	mov    $0x7d,%esi
  1188c0:	mov    %r12,%rdi
  1188c3:	callq  11c810 <vim_strchr@@Base>
  1188c8:	test   %rax,%rax
  1188cb:	jne    117853 <get_c_indent@@Base+0x10a3>
  1188d1:	lea    0x1066cc(%rip),%rsi        # 21efa4 <_IO_stdin_used@@Base+0x89e4>
  1188d8:	xor    %edx,%edx
  1188da:	mov    %r12,%rdi
  1188dd:	callq  10dd90 <smsg_attr@@Base+0x2f0>
  1188e2:	test   %eax,%eax
  1188e4:	jne    117853 <get_c_indent@@Base+0x10a3>
  1188ea:	lea    0x10da4c(%rip),%rsi        # 22633d <_IO_stdin_used@@Base+0xfd7d>
  1188f1:	xor    %edx,%edx
  1188f3:	mov    %r12,%rdi
  1188f6:	callq  10dd90 <smsg_attr@@Base+0x2f0>
  1188fb:	test   %eax,%eax
  1188fd:	jne    117853 <get_c_indent@@Base+0x10a3>
  118903:	lea    0x1(%r13),%rsi
  118907:	xor    %edi,%edi
  118909:	mov    %rsi,%rdx
  11890c:	callq  50200 <_init@@Base+0x1610>
  118911:	test   %eax,%eax
  118913:	je     117853 <get_c_indent@@Base+0x10a3>
  118919:	xor    %esi,%esi
  11891b:	mov    $0x1,%edx
  118920:	mov    %r12,%rdi
  118923:	callq  10e2c0 <smsg_attr@@Base+0x820>
  118928:	test   %eax,%eax
  11892a:	jne    117853 <get_c_indent@@Base+0x10a3>
  118930:	mov    0x395441(%rip),%rax        # 4add78 <curbuf@@Base>
  118937:	mov    0x395dd2(%rip),%rdx        # 4ae710 <curwin@@Base>
  11893e:	mov    0x1630(%rax),%eax
  118944:	mov    %eax,(%rsp)
  118947:	jmpq   117129 <get_c_indent@@Base+0x979>
  11894c:	callq  1007e0 <ml_get_curline@@Base>
  118951:	mov    %rax,%rdi
  118954:	mov    %rax,0x88(%rsp)
  11895c:	callq  607e0 <skipwhite@@Base>
  118961:	cmpb   $0x7d,(%rax)
  118964:	je     11873e <get_c_indent@@Base+0x1f8e>
  11896a:	mov    0x88(%rsp),%rdi
  118972:	lea    0x10d9f5(%rip),%rsi        # 22636e <_IO_stdin_used@@Base+0xfdae>
  118979:	xor    %edx,%edx
  11897b:	callq  10dd90 <smsg_attr@@Base+0x2f0>
  118980:	test   %eax,%eax
  118982:	jne    11873e <get_c_indent@@Base+0x1f8e>
  118988:	mov    0x88(%rsp),%rdi
  118990:	lea    0x10edf2(%rip),%rsi        # 227789 <_IO_stdin_used@@Base+0x111c9>
  118997:	xor    %edx,%edx
  118999:	callq  10dd90 <smsg_attr@@Base+0x2f0>
  11899e:	test   %eax,%eax
  1189a0:	je     11960e <get_c_indent@@Base+0x2e5e>
  1189a6:	callq  10e890 <get_indent@@Base>
  1189ab:	add    0x18(%rsp),%eax
  1189af:	mov    %eax,(%rsp)
  1189b2:	jmpq   118089 <get_c_indent@@Base+0x18d9>
  1189b7:	mov    0x88(%rsp),%rdi
  1189bf:	cmp    $0x9,%r14d
  1189c3:	je     119157 <get_c_indent@@Base+0x29a7>
  1189c9:	xor    %esi,%esi
  1189cb:	mov    $0x1,%edx
  1189d0:	callq  10e2c0 <smsg_attr@@Base+0x820>
  1189d5:	test   %ebp,%ebp
  1189d7:	mov    %eax,(%rsp)
  1189da:	mov    %eax,%r13d
  1189dd:	je     1189fc <get_c_indent@@Base+0x224c>
  1189df:	mov    0x395392(%rip),%rax        # 4add78 <curbuf@@Base>
  1189e6:	mov    0x1678(%rax),%r11d
  1189ed:	test   %r11d,%r11d
  1189f0:	je     1189fc <get_c_indent@@Base+0x224c>
  1189f2:	cmp    $0x2c,%r13b
  1189f6:	je     119170 <get_c_indent@@Base+0x29c0>
  1189fc:	cmp    $0xb,%r14d
  118a00:	je     1190d1 <get_c_indent@@Base+0x2921>
  118a06:	cmp    $0xc,%r14d
  118a0a:	je     118b13 <get_c_indent@@Base+0x2363>
  118a10:	test   %r13b,%r13b
  118a13:	je     118a29 <get_c_indent@@Base+0x2279>
  118a15:	cmp    $0x6,%r14d
  118a19:	je     119190 <get_c_indent@@Base+0x29e0>
  118a1f:	cmp    $0x2c,%r13b
  118a23:	jne    119190 <get_c_indent@@Base+0x29e0>
  118a29:	cmp    $0xa,%r14d
  118a2d:	jne    118b60 <get_c_indent@@Base+0x23b0>
  118a33:	mov    0x88(%rsp),%rbp
  118a3b:	mov    %ebx,(%rsp)
  118a3e:	mov    $0x29,%edx
  118a43:	mov    $0x28,%esi
  118a48:	mov    %rbp,%rdi
  118a4b:	callq  10e490 <smsg_attr@@Base+0x9f0>
  118a50:	mov    0x395cb9(%rip),%rax        # 4ae710 <curwin@@Base>
  118a57:	mov    0x20(%rsp),%rdx
  118a5c:	sub    0x38(%rax),%rdx
  118a60:	mov    0x395311(%rip),%rax        # 4add78 <curbuf@@Base>
  118a67:	mov    0x1664(%rax),%esi
  118a6d:	test   %rdx,%rdx
  118a70:	jle    118a87 <get_c_indent@@Base+0x22d7>
  118a72:	mov    %esi,%eax
  118a74:	mov    %esi,%ecx
  118a76:	shr    $0x1f,%eax
  118a79:	sub    %edx,%ecx
  118a7b:	add    %esi,%eax
  118a7d:	sar    %eax
  118a7f:	cltq   
  118a81:	cmp    %rax,%rdx
  118a84:	cmovl  %ecx,%esi
  118a87:	mov    $0x28,%edi
  118a8c:	callq  114130 <find_start_comment@@Base+0x150>
  118a91:	test   %rax,%rax
  118a94:	je     1190bd <get_c_indent@@Base+0x290d>
  118a9a:	mov    0xa0(%rsp),%rsi
  118aa2:	cmp    %rsi,(%rax)
  118aa5:	jl     1190bd <get_c_indent@@Base+0x290d>
  118aab:	je     1190ad <get_c_indent@@Base+0x28fd>
  118ab1:	cmp    $0x2c,%r13b
  118ab5:	sete   0x48(%rsp)
  118aba:	mov    (%rax),%rcx
  118abd:	mov    0x8(%rax),%rbx
  118ac1:	mov    0x395c48(%rip),%rax        # 4ae710 <curwin@@Base>
  118ac8:	mov    %rcx,0x38(%rax)
  118acc:	mov    %rbx,0x40(%rax)
  118ad0:	callq  1007e0 <ml_get_curline@@Base>
  118ad5:	xor    %esi,%esi
  118ad7:	mov    %rax,%rdi
  118ada:	mov    %rax,0x88(%rsp)
  118ae2:	callq  1162c0 <cin_iscase@@Base>
  118ae7:	test   %eax,%eax
  118ae9:	je     118b9c <get_c_indent@@Base+0x23ec>
  118aef:	mov    0x395c1a(%rip),%rdx        # 4ae710 <curwin@@Base>
  118af6:	xor    %ebp,%ebp
  118af8:	mov    (%rsp),%ebx
  118afb:	mov    0x38(%rdx),%rax
  118aff:	movl   $0x0,0x40(%rdx)
  118b06:	lea    0x1(%rax),%rcx
  118b0a:	mov    %rcx,0x38(%rdx)
  118b0e:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  118b13:	mov    0x395bf6(%rip),%rdx        # 4ae710 <curwin@@Base>
  118b1a:	mov    0x38(%rdx),%rax
  118b1e:	cmp    %rax,0xa0(%rsp)
  118b26:	jge    1184fb <get_c_indent@@Base+0x1d4b>
  118b2c:	cmp    $0x2c,%r13b
  118b30:	je     1184fb <get_c_indent@@Base+0x1d4b>
  118b36:	callq  10e890 <get_indent@@Base>
  118b3b:	mov    0x395bce(%rip),%rdx        # 4ae710 <curwin@@Base>
  118b42:	mov    %eax,%ebx
  118b44:	mov    0x38(%rdx),%rax
  118b48:	sub    $0x1,%rax
  118b4c:	cmp    %rax,0x30(%rsp)
  118b51:	je     1184fb <get_c_indent@@Base+0x1d4b>
  118b57:	test   %r13b,%r13b
  118b5a:	jne    118a15 <get_c_indent@@Base+0x2265>
  118b60:	mov    0x88(%rsp),%rdi
  118b68:	callq  607e0 <skipwhite@@Base>
  118b6d:	cmpb   $0x5b,(%rax)
  118b70:	mov    0x88(%rsp),%rbp
  118b78:	je     118b90 <get_c_indent@@Base+0x23e0>
  118b7a:	mov    %rbp,%rdi
  118b7d:	callq  4ed80 <_init@@Base+0x190>
  118b82:	cmpb   $0x5b,-0x1(%rbp,%rax,1)
  118b87:	mov    %ebx,(%rsp)
  118b8a:	jne    118a3e <get_c_indent@@Base+0x228e>
  118b90:	add    0x18(%rsp),%ebx
  118b94:	mov    %ebx,(%rsp)
  118b97:	jmpq   118a3e <get_c_indent@@Base+0x228e>
  118b9c:	mov    0x88(%rsp),%rdi
  118ba4:	callq  1164e0 <cin_isscopedecl@@Base>
  118ba9:	test   %eax,%eax
  118bab:	jne    118aef <get_c_indent@@Base+0x233f>
  118bb1:	cmp    $0x2c,%r13b
  118bb5:	je     118fda <get_c_indent@@Base+0x282a>
  118bbb:	mov    0x3951b6(%rip),%rax        # 4add78 <curbuf@@Base>
  118bc2:	mov    0x1678(%rax),%r10d
  118bc9:	test   %r10d,%r10d
  118bcc:	je     118d8b <get_c_indent@@Base+0x25db>
  118bd2:	callq  10e890 <get_indent@@Base>
  118bd7:	mov    %eax,%ebx
  118bd9:	cmp    $0x5,%r14d
  118bdd:	setne  0x68(%rsp)
  118be2:	cmp    $0x2c,%r13b
  118be6:	movzbl 0x68(%rsp),%eax
  118beb:	je     118bfc <get_c_indent@@Base+0x244c>
  118bed:	test   %al,%al
  118bef:	je     118bfc <get_c_indent@@Base+0x244c>
  118bf1:	cmpb   $0x7b,(%r12)
  118bf6:	je     119044 <get_c_indent@@Base+0x2894>
  118bfc:	mov    0x88(%rsp),%rdi
  118c04:	callq  10de60 <smsg_attr@@Base+0x3c0>
  118c09:	test   %eax,%eax
  118c0b:	je     118d3e <get_c_indent@@Base+0x258e>
  118c11:	lea    -0x6(%r14),%eax
  118c15:	and    $0xfffffffb,%eax
  118c18:	je     118d19 <get_c_indent@@Base+0x2569>
  118c1e:	movzbl (%r12),%ecx
  118c23:	cmp    $0x7b,%cl
  118c26:	jne    118c35 <get_c_indent@@Base+0x2485>
  118c28:	mov    0x395149(%rip),%rax        # 4add78 <curbuf@@Base>
  118c2f:	add    0x1610(%rax),%ebx
  118c35:	cmp    $0x5,%r14d
  118c39:	jne    118d01 <get_c_indent@@Base+0x2551>
  118c3f:	callq  1007e0 <ml_get_curline@@Base>
  118c44:	mov    %rax,%rdi
  118c47:	callq  607e0 <skipwhite@@Base>
  118c4c:	mov    %rax,%rdi
  118c4f:	mov    %rax,0x88(%rsp)
  118c57:	callq  4fffd <_init@@Base+0x140d>
  118c5c:	test   %eax,%eax
  118c5e:	je     118c6d <get_c_indent@@Base+0x24bd>
  118c60:	test   %r15d,%r15d
  118c63:	je     117ec8 <get_c_indent@@Base+0x1718>
  118c69:	sub    $0x1,%r15d
  118c6d:	mov    0x88(%rsp),%rdi
  118c75:	callq  10df60 <smsg_attr@@Base+0x4c0>
  118c7a:	test   %r15d,%r15d
  118c7d:	jne    118cef <get_c_indent@@Base+0x253f>
  118c7f:	test   %eax,%eax
  118c81:	je     118cef <get_c_indent@@Base+0x253f>
  118c83:	mov    0x88(%rsp),%rbp
  118c8b:	cmpb   $0x7d,0x0(%rbp)
  118c8f:	jne    118caa <get_c_indent@@Base+0x24fa>
  118c91:	mov    0x395a78(%rip),%r13        # 4ae710 <curwin@@Base>
  118c98:	callq  1007e0 <ml_get_curline@@Base>
  118c9d:	sub    %rax,%rbp
  118ca0:	mov    %rbp,%rax
  118ca3:	add    $0x1,%eax
  118ca6:	mov    %eax,0x40(%r13)
  118caa:	callq  114240 <find_start_comment@@Base+0x260>
  118caf:	test   %rax,%rax
  118cb2:	je     117ec8 <get_c_indent@@Base+0x1718>
  118cb8:	mov    (%rax),%rsi
  118cbb:	mov    $0x1,%edi
  118cc0:	callq  50479 <_init@@Base+0x1889>
  118cc5:	test   %eax,%eax
  118cc7:	je     117ec8 <get_c_indent@@Base+0x1718>
  118ccd:	mov    0x395a3c(%rip),%rdx        # 4ae710 <curwin@@Base>
  118cd4:	xor    %ebp,%ebp
  118cd6:	xor    %r15d,%r15d
  118cd9:	mov    0x38(%rdx),%rcx
  118cdd:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  118ce2:	mov    0x40(%rsp),%eax
  118ce6:	or     %r15d,%eax
  118ce9:	je     117ec8 <get_c_indent@@Base+0x1718>
  118cef:	mov    0x395a1a(%rip),%rdx        # 4ae710 <curwin@@Base>
  118cf6:	xor    %ebp,%ebp
  118cf8:	mov    0x38(%rdx),%rcx
  118cfc:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  118d01:	mov    %ebx,%esi
  118d03:	mov    0x20(%rsp),%r13
  118d08:	mov    0x28(%rsp),%r15d
  118d0d:	mov    0x395064(%rip),%rax        # 4add78 <curbuf@@Base>
  118d14:	jmpq   118274 <get_c_indent@@Base+0x1ac4>
  118d19:	mov    0x3c(%rsp),%esi
  118d1d:	mov    0x20(%rsp),%r13
  118d22:	mov    0x28(%rsp),%r15d
  118d27:	test   %esi,%esi
  118d29:	jg     118329 <get_c_indent@@Base+0x1b79>
  118d2f:	mov    (%rsp),%eax
  118d32:	add    0x18(%rsp),%eax
  118d36:	mov    %eax,(%rsp)
  118d39:	jmpq   117ed5 <get_c_indent@@Base+0x1725>
  118d3e:	mov    0x88(%rsp),%rdi
  118d46:	callq  607e0 <skipwhite@@Base>
  118d4b:	mov    %rax,%rdi
  118d4e:	callq  10df60 <smsg_attr@@Base+0x4c0>
  118d53:	test   %eax,%eax
  118d55:	mov    %eax,%ebp
  118d57:	jne    118c11 <get_c_indent@@Base+0x2461>
  118d5d:	cmp    $0x6,%r14d
  118d61:	je     118e87 <get_c_indent@@Base+0x26d7>
  118d67:	cmp    $0xa,%r14d
  118d6b:	jne    118dd7 <get_c_indent@@Base+0x2627>
  118d6d:	cmp    $0x2c,%r13b
  118d71:	je     118da7 <get_c_indent@@Base+0x25f7>
  118d73:	mov    (%rsp),%eax
  118d76:	mov    0x395993(%rip),%rdx        # 4ae710 <curwin@@Base>
  118d7d:	cmp    %eax,%ebx
  118d7f:	mov    0x38(%rdx),%rcx
  118d83:	cmovg  %eax,%ebx
  118d86:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  118d8b:	mov    0x39597e(%rip),%rax        # 4ae710 <curwin@@Base>
  118d92:	mov    0x50(%rsp),%rsi
  118d97:	mov    0x38(%rax),%rdi
  118d9b:	callq  116700 <cin_islabel@@Base+0x190>
  118da0:	mov    %eax,%ebx
  118da2:	jmpq   118bd9 <get_c_indent@@Base+0x2429>
  118da7:	mov    0x394fca(%rip),%rax        # 4add78 <curbuf@@Base>
  118dae:	mov    0x1640(%rax),%r8d
  118db5:	test   %r8d,%r8d
  118db8:	je     118ea1 <get_c_indent@@Base+0x26f1>
  118dbe:	mov    0x39594b(%rip),%rdx        # 4ae710 <curwin@@Base>
  118dc5:	mov    (%rsp),%ebx
  118dc8:	mov    $0x9,%r14d
  118dce:	mov    0x38(%rdx),%rcx
  118dd2:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  118dd7:	callq  1007e0 <ml_get_curline@@Base>
  118ddc:	mov    %rax,%rdi
  118ddf:	mov    %rax,0x88(%rsp)
  118de7:	mov    %rax,(%rsp)
  118deb:	callq  4ed80 <_init@@Base+0x190>
  118df0:	cmp    $0x2c,%r13b
  118df4:	mov    (%rsp),%rcx
  118df8:	je     118f79 <get_c_indent@@Base+0x27c9>
  118dfe:	test   %r14d,%r14d
  118e01:	jne    118f0c <get_c_indent@@Base+0x275c>
  118e07:	cmpb   $0x0,0x48(%rsp)
  118e0c:	je     118f0c <get_c_indent@@Base+0x275c>
  118e12:	mov    0x394f5f(%rip),%rax        # 4add78 <curbuf@@Base>
  118e19:	mov    0x1678(%rax),%edi
  118e1f:	test   %edi,%edi
  118e21:	je     118eeb <get_c_indent@@Base+0x273b>
  118e27:	mov    0x88(%rsp),%rdi
  118e2f:	callq  607e0 <skipwhite@@Base>
  118e34:	cmpb   $0x2f,(%rax)
  118e37:	je     118ed2 <get_c_indent@@Base+0x2722>
  118e3d:	mov    0x394f34(%rip),%rax        # 4add78 <curbuf@@Base>
  118e44:	mov    $0x5b,%edi
  118e49:	mov    0x1664(%rax),%esi
  118e4f:	callq  114130 <find_start_comment@@Base+0x150>
  118e54:	test   %rax,%rax
  118e57:	je     118ebc <get_c_indent@@Base+0x270c>
  118e59:	mov    0x3958b0(%rip),%rdx        # 4ae710 <curwin@@Base>
  118e60:	mov    (%rax),%rax
  118e63:	mov    0x38(%rdx),%rcx
  118e67:	mov    %rax,%rsi
  118e6a:	mov    %rax,0x30(%rsp)
  118e6f:	lea    -0x1(%rcx),%rax
  118e73:	cmp    %rax,%rsi
  118e76:	je     1184fb <get_c_indent@@Base+0x1d4b>
  118e7c:	mov    $0xc,%r14d
  118e82:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  118e87:	mov    %r13d,%eax
  118e8a:	mov    0x28(%rsp),%r15d
  118e8f:	mov    0x20(%rsp),%r13
  118e94:	cmp    $0x2c,%al
  118e96:	jne    117ed5 <get_c_indent@@Base+0x1725>
  118e9c:	jmpq   118d2f <get_c_indent@@Base+0x257f>
  118ea1:	mov    0x20(%rsp),%r13
  118ea6:	mov    0x28(%rsp),%r15d
  118eab:	movzbl (%r12),%ecx
  118eb0:	mov    0x395859(%rip),%rdx        # 4ae710 <curwin@@Base>
  118eb7:	jmpq   11777e <get_c_indent@@Base+0xfce>
  118ebc:	mov    0x39584d(%rip),%rdx        # 4ae710 <curwin@@Base>
  118ec3:	mov    $0xc,%r14d
  118ec9:	mov    0x38(%rdx),%rcx
  118ecd:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  118ed2:	movzbl 0x1(%rax),%eax
  118ed6:	cmp    $0x2a,%al
  118ed8:	je     117ec8 <get_c_indent@@Base+0x1718>
  118ede:	cmp    $0x2f,%al
  118ee0:	jne    118e3d <get_c_indent@@Base+0x268d>
  118ee6:	jmpq   117ec8 <get_c_indent@@Base+0x1718>
  118eeb:	callq  4fd72 <_init@@Base+0x1182>
  118ef0:	mov    0x395819(%rip),%rdx        # 4ae710 <curwin@@Base>
  118ef7:	mov    %eax,0x3c(%rsp)
  118efb:	xor    %ebp,%ebp
  118efd:	mov    $0xa,%r14d
  118f03:	mov    0x38(%rdx),%rcx
  118f07:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  118f0c:	test   %r14d,%r14d
  118f0f:	jne    118f44 <get_c_indent@@Base+0x2794>
  118f11:	mov    0x88(%rsp),%r13
  118f19:	cmpb   $0x0,0x0(%r13)
  118f1e:	je     118f44 <get_c_indent@@Base+0x2794>
  118f20:	mov    %r13,%rdi
  118f23:	callq  4ed80 <_init@@Base+0x190>
  118f28:	cmpb   $0x5c,-0x1(%r13,%rax,1)
  118f2e:	jne    118f44 <get_c_indent@@Base+0x2794>
  118f30:	mov    0x3957d9(%rip),%rax        # 4ae710 <curwin@@Base>
  118f37:	mov    0x38(%rax),%rdi
  118f3b:	callq  4fad9 <_init@@Base+0xee9>
  118f40:	mov    %eax,0x3c(%rsp)
  118f44:	cmp    $0xb,%r14d
  118f48:	je     117d20 <get_c_indent@@Base+0x1570>
  118f4e:	cmpb   $0x0,0x68(%rsp)
  118f53:	je     117d20 <get_c_indent@@Base+0x1570>
  118f59:	cmp    $0xc,%r14d
  118f5d:	je     117d20 <get_c_indent@@Base+0x1570>
  118f63:	mov    0x3957a6(%rip),%rdx        # 4ae710 <curwin@@Base>
  118f6a:	mov    $0x6,%r14d
  118f70:	mov    0x38(%rdx),%rcx
  118f74:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  118f79:	mov    %rcx,%rdi
  118f7c:	mov    %rax,(%rsp)
  118f80:	callq  607e0 <skipwhite@@Base>
  118f85:	cmpb   $0x5d,(%rax)
  118f88:	mov    (%rsp),%rdx
  118f8c:	je     117ec8 <get_c_indent@@Base+0x1718>
  118f92:	cmp    $0x1,%edx
  118f95:	jle    118dfe <get_c_indent@@Base+0x264e>
  118f9b:	mov    0x88(%rsp),%rax
  118fa3:	movslq %edx,%rdx
  118fa6:	cmpb   $0x5d,-0x2(%rax,%rdx,1)
  118fab:	jne    118dfe <get_c_indent@@Base+0x264e>
  118fb1:	jmpq   117ec8 <get_c_indent@@Base+0x1718>
  118fb6:	mov    0x88(%rsp),%rdi
  118fbe:	mov    $0x7d,%edx
  118fc3:	mov    $0x7b,%esi
  118fc8:	callq  10e490 <smsg_attr@@Base+0x9f0>
  118fcd:	test   %eax,%eax
  118fcf:	jne    1194e0 <get_c_indent@@Base+0x2d30>
  118fd5:	movb   $0x1,0x48(%rsp)
  118fda:	mov    0x39572f(%rip),%rax        # 4ae710 <curwin@@Base>
  118fe1:	mov    0x38(%rax),%rax
  118fe5:	cmp    $0x1,%rax
  118fe9:	jle    118bbb <get_c_indent@@Base+0x240b>
  118fef:	lea    -0x1(%rax),%rdi
  118ff3:	callq  1007a0 <ml_get@@Base>
  118ff8:	mov    %rax,0x88(%rsp)
  119000:	cmpb   $0x0,(%rax)
  119003:	mov    %rax,%rbx
  119006:	je     118bbb <get_c_indent@@Base+0x240b>
  11900c:	mov    %rax,%rdi
  11900f:	callq  4ed80 <_init@@Base+0x190>
  119014:	cmpb   $0x5c,-0x1(%rbx,%rax,1)
  119019:	jne    118bbb <get_c_indent@@Base+0x240b>
  11901f:	mov    0x3956ea(%rip),%rdx        # 4ae710 <curwin@@Base>
  119026:	mov    0x38(%rdx),%rax
  11902a:	movl   $0x0,0x40(%rdx)
  119031:	sub    $0x1,%rax
  119035:	cmp    $0x1,%rax
  119039:	mov    %rax,0x38(%rdx)
  11903d:	jg     118fef <get_c_indent@@Base+0x283f>
  11903f:	jmpq   118bbb <get_c_indent@@Base+0x240b>
  119044:	mov    0x88(%rsp),%rdi
  11904c:	callq  607e0 <skipwhite@@Base>
  119051:	cmpb   $0x7b,(%rax)
  119054:	mov    0x394d1d(%rip),%rax        # 4add78 <curbuf@@Base>
  11905b:	je     119063 <get_c_indent@@Base+0x28b3>
  11905d:	add    0x1610(%rax),%ebx
  119063:	mov    0x1640(%rax),%r9d
  11906a:	test   %r9d,%r9d
  11906d:	je     119079 <get_c_indent@@Base+0x28c9>
  11906f:	mov    0x1678(%rax),%ebp
  119075:	test   %ebp,%ebp
  119077:	je     119097 <get_c_indent@@Base+0x28e7>
  119079:	mov    %ebx,(%rsp)
  11907c:	mov    0x20(%rsp),%r13
  119081:	mov    0x28(%rsp),%r15d
  119086:	movzbl (%r12),%ecx
  11908b:	mov    0x39567e(%rip),%rdx        # 4ae710 <curwin@@Base>
  119092:	jmpq   11777e <get_c_indent@@Base+0xfce>
  119097:	mov    0x395672(%rip),%rdx        # 4ae710 <curwin@@Base>
  11909e:	mov    $0x9,%r14d
  1190a4:	mov    0x38(%rdx),%rcx
  1190a8:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  1190ad:	mov    0xa8(%rsp),%esi
  1190b4:	cmp    %esi,0x8(%rax)
  1190b7:	jge    118ab1 <get_c_indent@@Base+0x2301>
  1190bd:	cmp    $0x2c,%r13b
  1190c1:	je     118fb6 <get_c_indent@@Base+0x2806>
  1190c7:	movb   $0x0,0x48(%rsp)
  1190cc:	jmpq   118bbb <get_c_indent@@Base+0x240b>
  1190d1:	mov    0x88(%rsp),%rdi
  1190d9:	callq  10e010 <smsg_attr@@Base+0x570>
  1190de:	test   %eax,%eax
  1190e0:	je     118b57 <get_c_indent@@Base+0x23a7>
  1190e6:	jmpq   1181d1 <get_c_indent@@Base+0x1a21>
  1190eb:	mov    0xd0(%rsp),%edi
  1190f2:	mov    0x20(%rsp),%r13
  1190f7:	mov    0x28(%rsp),%r15d
  1190fc:	callq  50121 <_init@@Base+0x1531>
  119101:	movzbl (%r12),%ecx
  119106:	mov    %eax,(%rsp)
  119109:	mov    0x395600(%rip),%rdx        # 4ae710 <curwin@@Base>
  119110:	mov    0x394c61(%rip),%rax        # 4add78 <curbuf@@Base>
  119117:	jmpq   11777e <get_c_indent@@Base+0xfce>
  11911c:	mov    %r12,%rdi
  11911f:	callq  4ffce <_init@@Base+0x13de>
  119124:	test   %eax,%eax
  119126:	setne  %al
  119129:	movzbl %al,%eax
  11912c:	mov    %eax,0x40(%rsp)
  119130:	mov    0x394c41(%rip),%rax        # 4add78 <curbuf@@Base>
  119137:	jmpq   117bc7 <get_c_indent@@Base+0x1417>
  11913c:	mov    0x1678(%rax),%ecx
  119142:	test   %ecx,%ecx
  119144:	jne    11914d <get_c_indent@@Base+0x299d>
  119146:	mov    0x18(%rsp),%ebx
  11914a:	add    %ebx,(%rsp)
  11914d:	movzbl (%r12),%ecx
  119152:	jmpq   11777e <get_c_indent@@Base+0xfce>
  119157:	xor    %edx,%edx
  119159:	mov    $0x1,%esi
  11915e:	callq  10e2c0 <smsg_attr@@Base+0x820>
  119163:	test   %eax,%eax
  119165:	jne    117ec8 <get_c_indent@@Base+0x1718>
  11916b:	jmpq   117d20 <get_c_indent@@Base+0x1570>
  119170:	mov    0x88(%rsp),%rdi
  119178:	callq  10e010 <smsg_attr@@Base+0x570>
  11917d:	test   %eax,%eax
  11917f:	jne    1181d1 <get_c_indent@@Base+0x1a21>
  119185:	mov    $0xb,%r14d
  11918b:	jmpq   118a15 <get_c_indent@@Base+0x2265>
  119190:	cmpb   $0x3b,(%rsp)
  119194:	je     11944a <get_c_indent@@Base+0x2c9a>
  11919a:	cmp    $0x8,%r14d
  11919e:	je     119419 <get_c_indent@@Base+0x2c69>
  1191a4:	test   %r15d,%r15d
  1191a7:	je     1191ce <get_c_indent@@Base+0x2a1e>
  1191a9:	callq  1007e0 <ml_get_curline@@Base>
  1191ae:	mov    %rax,%rdi
  1191b1:	callq  10db80 <smsg_attr@@Base+0xe0>
  1191b6:	mov    %rax,%rdi
  1191b9:	mov    %rax,0x88(%rsp)
  1191c1:	callq  4fffd <_init@@Base+0x140d>
  1191c6:	test   %eax,%eax
  1191c8:	jne    1194af <get_c_indent@@Base+0x2cff>
  1191ce:	lea    -0x6(%r14),%eax
  1191d2:	and    $0xfffffffb,%eax
  1191d5:	je     1184a4 <get_c_indent@@Base+0x1cf4>
  1191db:	cmp    $0x5,%r14d
  1191df:	je     118ce2 <get_c_indent@@Base+0x2532>
  1191e5:	callq  1007e0 <ml_get_curline@@Base>
  1191ea:	mov    $0x29,%edx
  1191ef:	mov    $0x28,%esi
  1191f4:	mov    %rax,%rdi
  1191f7:	mov    %rax,0x88(%rsp)
  1191ff:	callq  10e490 <smsg_attr@@Base+0x9f0>
  119204:	test   %eax,%eax
  119206:	jne    119309 <get_c_indent@@Base+0x2b59>
  11920c:	mov    0x394b65(%rip),%rax        # 4add78 <curbuf@@Base>
  119213:	mov    0x167c(%rax),%ebp
  119219:	test   %ebp,%ebp
  11921b:	je     119234 <get_c_indent@@Base+0x2a84>
  11921d:	mov    0x88(%rsp),%rdi
  119225:	xor    %esi,%esi
  119227:	xor    %ebp,%ebp
  119229:	callq  1162c0 <cin_iscase@@Base>
  11922e:	test   %eax,%eax
  119230:	setne  %bpl
  119234:	mov    0x3954d5(%rip),%rax        # 4ae710 <curwin@@Base>
  11923b:	mov    0x50(%rsp),%rsi
  119240:	mov    0x38(%rax),%rdi
  119244:	callq  116700 <cin_islabel@@Base+0x190>
  119249:	cmpb   $0x7b,(%r12)
  11924e:	mov    %eax,%ebx
  119250:	jne    11925f <get_c_indent@@Base+0x2aaf>
  119252:	mov    0x394b1f(%rip),%rax        # 4add78 <curbuf@@Base>
  119259:	add    0x1610(%rax),%ebx
  11925f:	mov    0x88(%rsp),%rdi
  119267:	callq  607e0 <skipwhite@@Base>
  11926c:	mov    %rax,0x88(%rsp)
  119274:	movzbl (%rax),%edx
  119277:	cmp    $0x7b,%dl
  11927a:	je     1193c4 <get_c_indent@@Base+0x2c14>
  119280:	test   %ebp,%ebp
  119282:	je     11937b <get_c_indent@@Base+0x2bcb>
  119288:	mov    $0x4,%r14d
  11928e:	callq  1007e0 <ml_get_curline@@Base>
  119293:	mov    $0x7d,%edx
  119298:	mov    $0x7b,%esi
  11929d:	mov    %rax,%rdi
  1192a0:	mov    %rax,0x88(%rsp)
  1192a8:	callq  10e490 <smsg_attr@@Base+0x9f0>
  1192ad:	test   %eax,%eax
  1192af:	je     11939c <get_c_indent@@Base+0x2bec>
  1192b5:	callq  114240 <find_start_comment@@Base+0x260>
  1192ba:	test   %rax,%rax
  1192bd:	je     118cef <get_c_indent@@Base+0x253f>
  1192c3:	mov    (%rax),%rsi
  1192c6:	mov    0x8(%rax),%rdi
  1192ca:	mov    0x39543f(%rip),%rax        # 4ae710 <curwin@@Base>
  1192d1:	mov    %rsi,0x38(%rax)
  1192d5:	mov    %rdi,0x40(%rax)
  1192d9:	callq  1007e0 <ml_get_curline@@Base>
  1192de:	mov    %rax,%rdi
  1192e1:	callq  10db80 <smsg_attr@@Base+0xe0>
  1192e6:	mov    %rax,0x88(%rsp)
  1192ee:	cmpb   $0x7d,(%rax)
  1192f1:	je     1191e5 <get_c_indent@@Base+0x2a35>
  1192f7:	mov    %rax,%rdi
  1192fa:	callq  10df60 <smsg_attr@@Base+0x4c0>
  1192ff:	test   %eax,%eax
  119301:	je     1191e5 <get_c_indent@@Base+0x2a35>
  119307:	jmp    11935a <get_c_indent@@Base+0x2baa>
  119309:	mov    0x394a68(%rip),%rax        # 4add78 <curbuf@@Base>
  119310:	mov    $0x28,%edi
  119315:	mov    0x1664(%rax),%esi
  11931b:	callq  114130 <find_start_comment@@Base+0x150>
  119320:	test   %rax,%rax
  119323:	je     11920c <get_c_indent@@Base+0x2a5c>
  119329:	mov    (%rax),%rsi
  11932c:	mov    0x8(%rax),%rdi
  119330:	mov    0x3953d9(%rip),%rax        # 4ae710 <curwin@@Base>
  119337:	mov    %rsi,0x38(%rax)
  11933b:	mov    %rdi,0x40(%rax)
  11933f:	callq  1007e0 <ml_get_curline@@Base>
  119344:	xor    %esi,%esi
  119346:	mov    %rax,%rdi
  119349:	mov    %rax,0x88(%rsp)
  119351:	callq  1162c0 <cin_iscase@@Base>
  119356:	test   %eax,%eax
  119358:	je     1193ae <get_c_indent@@Base+0x2bfe>
  11935a:	mov    0x3953af(%rip),%rdx        # 4ae710 <curwin@@Base>
  119361:	xor    %ebp,%ebp
  119363:	mov    0x38(%rdx),%rax
  119367:	movl   $0x0,0x40(%rdx)
  11936e:	lea    0x1(%rax),%rcx
  119372:	mov    %rcx,0x38(%rdx)
  119376:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  11937b:	cmp    $0x7d,%dl
  11937e:	je     119391 <get_c_indent@@Base+0x2be1>
  119380:	mov    %rax,%rdi
  119383:	callq  10df60 <smsg_attr@@Base+0x4c0>
  119388:	test   %r15d,%r15d
  11938b:	jne    119391 <get_c_indent@@Base+0x2be1>
  11938d:	test   %eax,%eax
  11938f:	jne    1193db <get_c_indent@@Base+0x2c2b>
  119391:	mov    $0x5,%r14d
  119397:	jmpq   11928e <get_c_indent@@Base+0x2ade>
  11939c:	mov    0x39536d(%rip),%rdx        # 4ae710 <curwin@@Base>
  1193a3:	mov    %eax,%ebp
  1193a5:	mov    0x38(%rdx),%rcx
  1193a9:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  1193ae:	mov    0x88(%rsp),%rdi
  1193b6:	callq  1164e0 <cin_isscopedecl@@Base>
  1193bb:	test   %eax,%eax
  1193bd:	jne    11935a <get_c_indent@@Base+0x2baa>
  1193bf:	jmpq   11920c <get_c_indent@@Base+0x2a5c>
  1193c4:	mov    0x3949ad(%rip),%rdx        # 4add78 <curbuf@@Base>
  1193cb:	sub    0x1610(%rdx),%ebx
  1193d1:	test   %ebp,%ebp
  1193d3:	jne    119288 <get_c_indent@@Base+0x2ad8>
  1193d9:	jmp    119380 <get_c_indent@@Base+0x2bd0>
  1193db:	callq  114240 <find_start_comment@@Base+0x260>
  1193e0:	test   %rax,%rax
  1193e3:	je     117ec8 <get_c_indent@@Base+0x1718>
  1193e9:	mov    (%rax),%rsi
  1193ec:	mov    $0x1,%edi
  1193f1:	callq  50479 <_init@@Base+0x1889>
  1193f6:	test   %eax,%eax
  1193f8:	je     117ec8 <get_c_indent@@Base+0x1718>
  1193fe:	mov    0x39530b(%rip),%rdx        # 4ae710 <curwin@@Base>
  119405:	xor    %r15d,%r15d
  119408:	xor    %ebp,%ebp
  11940a:	mov    $0x5,%r14d
  119410:	mov    0x38(%rdx),%rcx
  119414:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  119419:	callq  1007e0 <ml_get_curline@@Base>
  11941e:	mov    %rax,%rdi
  119421:	callq  607e0 <skipwhite@@Base>
  119426:	mov    %rax,%rdi
  119429:	callq  4ffce <_init@@Base+0x13de>
  11942e:	test   %eax,%eax
  119430:	je     119481 <get_c_indent@@Base+0x2cd1>
  119432:	mov    0x3952d7(%rip),%rdx        # 4ae710 <curwin@@Base>
  119439:	xor    %ebp,%ebp
  11943b:	mov    $0x4,%r14d
  119441:	mov    0x38(%rdx),%rcx
  119445:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  11944a:	callq  1007e0 <ml_get_curline@@Base>
  11944f:	mov    %rax,%r13
  119452:	movzbl (%rax),%eax
  119455:	mov    %r13,%rdi
  119458:	test   %al,%al
  11945a:	je     11919a <get_c_indent@@Base+0x29ea>
  119460:	callq  10db80 <smsg_attr@@Base+0xe0>
  119465:	mov    %rax,%rbp
  119468:	movzbl (%rax),%eax
  11946b:	cmp    $0x29,%al
  11946d:	je     1194cc <get_c_indent@@Base+0x2d1c>
  11946f:	test   %al,%al
  119471:	je     11919a <get_c_indent@@Base+0x29ea>
  119477:	lea    0x1(%rbp),%rdi
  11947b:	movzbl 0x1(%rbp),%eax
  11947f:	jmp    119458 <get_c_indent@@Base+0x2ca8>
  119481:	test   %r15d,%r15d
  119484:	je     1191e5 <get_c_indent@@Base+0x2a35>
  11948a:	callq  1007e0 <ml_get_curline@@Base>
  11948f:	mov    %rax,%rdi
  119492:	callq  10db80 <smsg_attr@@Base+0xe0>
  119497:	mov    %rax,%rdi
  11949a:	mov    %rax,0x88(%rsp)
  1194a2:	callq  4fffd <_init@@Base+0x140d>
  1194a7:	test   %eax,%eax
  1194a9:	je     1191e5 <get_c_indent@@Base+0x2a35>
  1194af:	callq  10e890 <get_indent@@Base>
  1194b4:	mov    0x395255(%rip),%rdx        # 4ae710 <curwin@@Base>
  1194bb:	mov    %eax,%ebx
  1194bd:	sub    $0x1,%r15d
  1194c1:	xor    %ebp,%ebp
  1194c3:	mov    0x38(%rdx),%rcx
  1194c7:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  1194cc:	lea    0x1(%rbp),%rdi
  1194d0:	callq  607e0 <skipwhite@@Base>
  1194d5:	cmpb   $0x3b,(%rax)
  1194d8:	je     1194f8 <get_c_indent@@Base+0x2d48>
  1194da:	movzbl 0x0(%rbp),%eax
  1194de:	jmp    11946f <get_c_indent@@Base+0x2cbf>
  1194e0:	callq  114240 <find_start_comment@@Base+0x260>
  1194e5:	test   %rax,%rax
  1194e8:	movb   $0x1,0x48(%rsp)
  1194ed:	jne    118aba <get_c_indent@@Base+0x230a>
  1194f3:	jmpq   118fda <get_c_indent@@Base+0x282a>
  1194f8:	lea    0x1(%rax),%rdi
  1194fc:	callq  10db80 <smsg_attr@@Base+0xe0>
  119501:	cmpb   $0x0,(%rax)
  119504:	jne    1194da <get_c_indent@@Base+0x2d2a>
  119506:	mov    0x395203(%rip),%rax        # 4ae710 <curwin@@Base>
  11950d:	sub    %r13,%rbp
  119510:	mov    $0x28,%edi
  119515:	mov    %ebp,0x40(%rax)
  119518:	mov    0x394859(%rip),%rax        # 4add78 <curbuf@@Base>
  11951f:	mov    0x1664(%rax),%esi
  119525:	callq  114130 <find_start_comment@@Base+0x150>
  11952a:	test   %rax,%rax
  11952d:	mov    %rax,%r13
  119530:	je     119563 <get_c_indent@@Base+0x2db3>
  119532:	mov    (%rax),%rdi
  119535:	callq  1007a0 <ml_get@@Base>
  11953a:	mov    %rax,%rdi
  11953d:	callq  10db80 <smsg_attr@@Base+0xe0>
  119542:	cmpb   $0x7d,(%rax)
  119545:	jne    119550 <get_c_indent@@Base+0x2da0>
  119547:	lea    0x1(%rax),%rdi
  11954b:	callq  10db80 <smsg_attr@@Base+0xe0>
  119550:	lea    0x105dca(%rip),%rsi        # 21f321 <_IO_stdin_used@@Base+0x8d61>
  119557:	mov    %rax,%rdi
  11955a:	callq  10dfc0 <smsg_attr@@Base+0x520>
  11955f:	test   %eax,%eax
  119561:	jne    119576 <get_c_indent@@Base+0x2dc6>
  119563:	movslq %ebp,%rbp
  119566:	callq  1007e0 <ml_get_curline@@Base>
  11956b:	mov    %rax,%r13
  11956e:	add    %rax,%rbp
  119571:	jmpq   1194da <get_c_indent@@Base+0x2d2a>
  119576:	mov    0x395193(%rip),%rdx        # 4ae710 <curwin@@Base>
  11957d:	mov    0x0(%r13),%rcx
  119581:	lea    -0x6(%r14),%eax
  119585:	and    $0xfffffffb,%eax
  119588:	mov    %rcx,0x38(%rdx)
  11958c:	je     11815c <get_c_indent@@Base+0x19ac>
  119592:	test   %r15d,%r15d
  119595:	je     11968f <get_c_indent@@Base+0x2edf>
  11959b:	add    $0x1,%r15d
  11959f:	xor    %ebp,%ebp
  1195a1:	jmpq   117c2e <get_c_indent@@Base+0x147e>
  1195a6:	callq  116570 <cin_islabel@@Base>
  1195ab:	test   %eax,%eax
  1195ad:	je     118583 <get_c_indent@@Base+0x1dd3>
  1195b3:	callq  1007e0 <ml_get_curline@@Base>
  1195b8:	mov    %rax,%rdi
  1195bb:	callq  1163b0 <cin_iscase@@Base+0xf0>
  1195c0:	test   %rax,%rax
  1195c3:	mov    %rax,0x88(%rsp)
  1195cb:	je     117d20 <get_c_indent@@Base+0x1570>
  1195d1:	mov    %rax,%rdi
  1195d4:	callq  10db80 <smsg_attr@@Base+0xe0>
  1195d9:	cmpb   $0x0,(%rax)
  1195dc:	jne    118583 <get_c_indent@@Base+0x1dd3>
  1195e2:	jmpq   117d20 <get_c_indent@@Base+0x1570>
  1195e7:	mov    0x88(%rsp),%rdi
  1195ef:	xor    %esi,%esi
  1195f1:	mov    $0x1,%edx
  1195f6:	callq  10e2c0 <smsg_attr@@Base+0x820>
  1195fb:	test   %ebp,%ebp
  1195fd:	mov    %eax,(%rsp)
  119600:	mov    %eax,%r13d
  119603:	jne    1189df <get_c_indent@@Base+0x222f>
  119609:	jmpq   118a10 <get_c_indent@@Base+0x2260>
  11960e:	mov    0x88(%rsp),%rdi
  119616:	callq  607e0 <skipwhite@@Base>
  11961b:	mov    %rax,0x90(%rsp)
  119623:	cmpb   $0x3b,(%rax)
  119626:	je     11979a <get_c_indent@@Base+0x2fea>
  11962c:	mov    0x3950dd(%rip),%rax        # 4ae710 <curwin@@Base>
  119633:	mov    0x38(%rax),%rbx
  119637:	xor    %edx,%edx
  119639:	mov    %rbx,%rsi
  11963c:	mov    %rbp,%rdi
  11963f:	callq  50200 <_init@@Base+0x1610>
  119644:	test   %eax,%eax
  119646:	je     1196c0 <get_c_indent@@Base+0x2f10>
  119648:	mov    0x394729(%rip),%rax        # 4add78 <curbuf@@Base>
  11964f:	mov    0x162c(%rax),%eax
  119655:	mov    %eax,(%rsp)
  119658:	jmpq   118089 <get_c_indent@@Base+0x18d9>
  11965d:	mov    0x88(%rsp),%rdi
  119665:	mov    $0x7d,%edx
  11966a:	mov    $0x7b,%esi
  11966f:	callq  10e490 <smsg_attr@@Base+0x9f0>
  119674:	test   %eax,%eax
  119676:	je     117d20 <get_c_indent@@Base+0x1570>
  11967c:	callq  114240 <find_start_comment@@Base+0x260>
  119681:	test   %rax,%rax
  119684:	jne    117cc3 <get_c_indent@@Base+0x1513>
  11968a:	jmpq   117d20 <get_c_indent@@Base+0x1570>
  11968f:	callq  10e890 <get_indent@@Base>
  119694:	cmpb   $0x7b,(%r12)
  119699:	mov    %eax,%ebx
  11969b:	jne    1196aa <get_c_indent@@Base+0x2efa>
  11969d:	mov    0x3946d4(%rip),%rax        # 4add78 <curbuf@@Base>
  1196a4:	add    0x1610(%rax),%ebx
  1196aa:	mov    0x39505f(%rip),%rdx        # 4ae710 <curwin@@Base>
  1196b1:	mov    $0x5,%r14d
  1196b7:	mov    0x38(%rdx),%rcx
  1196bb:	jmpq   11959b <get_c_indent@@Base+0x2deb>
  1196c0:	mov    0x88(%rsp),%rdi
  1196c8:	lea    0x114b56(%rip),%rsi        # 22e225 <_IO_stdin_used@@Base+0x17c65>
  1196cf:	xor    %edx,%edx
  1196d1:	callq  10dd90 <smsg_attr@@Base+0x2f0>
  1196d6:	test   %eax,%eax
  1196d8:	jne    119733 <get_c_indent@@Base+0x2f83>
  1196da:	mov    0x88(%rsp),%rax
  1196e2:	mov    $0x29,%edx
  1196e7:	mov    $0x28,%esi
  1196ec:	mov    %rax,%rdi
  1196ef:	callq  10e490 <smsg_attr@@Base+0x9f0>
  1196f4:	mov    0x39467d(%rip),%rax        # 4add78 <curbuf@@Base>
  1196fb:	mov    $0x28,%edi
  119700:	mov    0x1664(%rax),%esi
  119706:	callq  114130 <find_start_comment@@Base+0x150>
  11970b:	test   %rax,%rax
  11970e:	je     119726 <get_c_indent@@Base+0x2f76>
  119710:	mov    (%rax),%rcx
  119713:	mov    0x8(%rax),%rbx
  119717:	mov    0x394ff2(%rip),%rax        # 4ae710 <curwin@@Base>
  11971e:	mov    %rcx,0x38(%rax)
  119722:	mov    %rbx,0x40(%rax)
  119726:	callq  10e890 <get_indent@@Base>
  11972b:	mov    %eax,(%rsp)
  11972e:	jmpq   118089 <get_c_indent@@Base+0x18d9>
  119733:	mov    0x394fd6(%rip),%rax        # 4ae710 <curwin@@Base>
  11973a:	mov    0x38(%rax),%rdi
  11973e:	sub    $0x1,%rdi
  119742:	callq  1007a0 <ml_get@@Base>
  119747:	lea    0x10cbef(%rip),%rsi        # 22633d <_IO_stdin_used@@Base+0xfd7d>
  11974e:	xor    %edx,%edx
  119750:	mov    %rax,%rdi
  119753:	mov    %rax,0x88(%rsp)
  11975b:	callq  10dd90 <smsg_attr@@Base+0x2f0>
  119760:	test   %eax,%eax
  119762:	jne    11873e <get_c_indent@@Base+0x1f8e>
  119768:	mov    0x88(%rsp),%rbx
  119770:	cmpb   $0x0,(%rbx)
  119773:	je     119788 <get_c_indent@@Base+0x2fd8>
  119775:	mov    %rbx,%rdi
  119778:	callq  4ed80 <_init@@Base+0x190>
  11977d:	cmpb   $0x5c,-0x1(%rbx,%rax,1)
  119782:	je     11873e <get_c_indent@@Base+0x1f8e>
  119788:	callq  1007e0 <ml_get_curline@@Base>
  11978d:	mov    %rax,0x88(%rsp)
  119795:	jmpq   1196e2 <get_c_indent@@Base+0x2f32>
  11979a:	lea    0x1(%rax),%rdi
  11979e:	callq  10db80 <smsg_attr@@Base+0xe0>
  1197a3:	cmpb   $0x0,(%rax)
  1197a6:	mov    0x394f63(%rip),%rax        # 4ae710 <curwin@@Base>
  1197ad:	mov    0x38(%rax),%rbx
  1197b1:	jne    119637 <get_c_indent@@Base+0x2e87>
  1197b7:	lea    0x90(%rsp),%rsi
  1197bf:	mov    0x40(%rax),%r14d
  1197c3:	mov    0x44(%rax),%r15d
  1197c7:	mov    %rbx,%rdx
  1197ca:	mov    %rsi,(%rsp)
  1197ce:	cmp    $0x1,%rdx
  1197d2:	jle    11981f <get_c_indent@@Base+0x306f>
  1197d4:	lea    -0x1(%rdx),%rdi
  1197d8:	mov    %rdi,0x38(%rax)
  1197dc:	callq  1007a0 <ml_get@@Base>
  1197e1:	mov    %rax,%rdi
  1197e4:	mov    %rax,0x90(%rsp)
  1197ec:	callq  10db80 <smsg_attr@@Base+0xe0>
  1197f1:	cmpb   $0x0,(%rax)
  1197f4:	mov    0x394f15(%rip),%rax        # 4ae710 <curwin@@Base>
  1197fb:	jne    119803 <get_c_indent@@Base+0x3053>
  1197fd:	mov    0x38(%rax),%rdx
  119801:	jmp    1197ce <get_c_indent@@Base+0x301e>
  119803:	mov    (%rsp),%rdi
  119807:	lea    0x38(%rax),%rsi
  11980b:	callq  10dc40 <smsg_attr@@Base+0x1a0>
  119810:	test   %eax,%eax
  119812:	mov    0x394ef7(%rip),%rax        # 4ae710 <curwin@@Base>
  119819:	mov    0x38(%rax),%rdx
  11981d:	jne    1197ce <get_c_indent@@Base+0x301e>
  11981f:	test   %rdx,%rdx
  119822:	jle    119849 <get_c_indent@@Base+0x3099>
  119824:	mov    0x90(%rsp),%rdi
  11982c:	lea    0x111066(%rip),%rsi        # 22a899 <_IO_stdin_used@@Base+0x142d9>
  119833:	xor    %edx,%edx
  119835:	callq  10dd90 <smsg_attr@@Base+0x2f0>
  11983a:	test   %eax,%eax
  11983c:	jne    11873e <get_c_indent@@Base+0x1f8e>
  119842:	mov    0x394ec7(%rip),%rax        # 4ae710 <curwin@@Base>
  119849:	mov    %rbx,0x38(%rax)
  11984d:	mov    %r14d,0x40(%rax)
  119851:	mov    %r15d,0x44(%rax)
  119855:	jmpq   119637 <get_c_indent@@Base+0x2e87>
  11985a:	nopw   0x0(%rax,%rax,1)
