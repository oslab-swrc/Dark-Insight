# When we see the source code, it doesn't look like synchronization loop  
00000000012f8a10 <my_coll_parser_scan_shift_sequence>:
 12f8a10:	push   %rbp
 12f8a11:	lea    0x80(%rdi),%rsi
 12f8a18:	mov    $0x30,%edx
 12f8a1d:	mov    %rsp,%rbp
 12f8a20:	push   %r12
 12f8a22:	push   %rbx
 12f8a23:	mov    %rdi,%rbx
 12f8a26:	mov    %rsi,%rdi
 12f8a29:	add    $0xffffffffffffff80,%rsp
 12f8a2d:	test   $0x1,%sil
 12f8a31:	jne    12f8e28 <my_coll_parser_scan_shift_sequence+0x418>
 12f8a37:	test   $0x2,%dil
 12f8a3b:	jne    12f8df0 <my_coll_parser_scan_shift_sequence+0x3e0>
 12f8a41:	test   $0x4,%dil
 12f8a45:	jne    12f8e10 <my_coll_parser_scan_shift_sequence+0x400>
 12f8a4b:	mov    %edx,%ecx
 12f8a4d:	xor    %eax,%eax
 12f8a4f:	shr    $0x3,%ecx
 12f8a52:	test   $0x4,%dl
 12f8a55:	rep stos %rax,%es:(%rdi)
 12f8a58:	je     12f8a64 <my_coll_parser_scan_shift_sequence+0x54>
 12f8a5a:	movl   $0x0,(%rdi)
 12f8a60:	add    $0x4,%rdi
 12f8a64:	test   $0x2,%dl
 12f8a67:	je     12f8a73 <my_coll_parser_scan_shift_sequence+0x63>
 12f8a69:	xor    %eax,%eax
 12f8a6b:	add    $0x2,%rdi
 12f8a6f:	mov    %ax,-0x2(%rdi)
 12f8a73:	and    $0x1,%edx
 12f8a76:	je     12f8a7b <my_coll_parser_scan_shift_sequence+0x6b>
 12f8a78:	movb   $0x0,(%rdi)
 12f8a7b:	lea    0x547e43(%rip),%rdx        # 18408c5 <t_ctype+0x1425>
 12f8a82:	mov    %rbx,%rdi
 12f8a85:	callq  12f86e0 <my_coll_parser_scan_character_list.constprop.25>
 12f8a8a:	test   %eax,%eax
 12f8a8c:	je     12f8cbc <my_coll_parser_scan_shift_sequence+0x2ac>
 12f8a92:	mov    0x50(%rbx),%rax
 12f8a96:	mov    %rax,-0x90(%rbp)
 12f8a9d:	mov    0x58(%rbx),%rax
 12f8aa1:	mov    %rax,-0x88(%rbp)
 12f8aa8:	mov    0x60(%rbx),%rax
 12f8aac:	mov    %rax,-0x80(%rbp)
 12f8ab0:	mov    0x68(%rbx),%rax
 12f8ab4:	mov    %rax,-0x78(%rbp)
 12f8ab8:	mov    0x70(%rbx),%rax
 12f8abc:	mov    %rax,-0x70(%rbp)
 12f8ac0:	mov    0x78(%rbx),%rax
 12f8ac4:	mov    %rax,-0x68(%rbp)
 12f8ac8:	mov    0x80(%rbx),%rax
 12f8acf:	mov    %rax,-0x60(%rbp)
 12f8ad3:	mov    0x88(%rbx),%rax
 12f8ada:	mov    %rax,-0x58(%rbp)
 12f8ade:	mov    0x90(%rbx),%rax
 12f8ae5:	mov    %rax,-0x50(%rbp)
 12f8ae9:	mov    0x98(%rbx),%rax
 12f8af0:	mov    %rax,-0x48(%rbp)
 12f8af4:	mov    0xa0(%rbx),%rax
 12f8afb:	mov    %rax,-0x40(%rbp)
 12f8aff:	mov    0xa8(%rbx),%rax
 12f8b06:	mov    %rax,-0x38(%rbp)
 12f8b0a:	mov    0xb0(%rbx),%rax
 12f8b11:	mov    %rax,-0x30(%rbp)
 12f8b15:	mov    0xb8(%rbx),%rax
 12f8b1c:	mov    %rax,-0x28(%rbp)
 12f8b20:	mov    0xc0(%rbx),%rax
 12f8b27:	mov    %rax,-0x20(%rbp)
 12f8b2b:	mov    0xc8(%rbx),%rax
 12f8b32:	mov    %rax,-0x18(%rbp)
 12f8b36:	mov    (%rbx),%eax
 12f8b38:	cmp    $0x8,%eax
 12f8b3b:	je     12f8e40 <my_coll_parser_scan_shift_sequence+0x430>
 12f8b41:	cmp    $0x9,%eax
 12f8b44:	je     12f8d80 <my_coll_parser_scan_shift_sequence+0x370>
 12f8b4a:	mov    0xd0(%rbx),%r12
 12f8b51:	mov    0x10(%r12),%rsi
 12f8b56:	cmp    0x18(%r12),%rsi
 12f8b5b:	jae    12f8cc8 <my_coll_parser_scan_shift_sequence+0x2b8>
 12f8b61:	mov    0x20(%r12),%rax
 12f8b66:	lea    0x1(%rsi),%rdx
 12f8b6a:	shl    $0x7,%rsi
 12f8b6e:	add    %rsi,%rax
 12f8b71:	mov    %rdx,0x10(%r12)
 12f8b76:	mov    0x50(%rbx),%rdx
 12f8b7a:	mov    %rdx,(%rax)
 12f8b7d:	mov    0x58(%rbx),%rdx
 12f8b81:	mov    %rdx,0x8(%rax)
 12f8b85:	mov    0x60(%rbx),%rdx
 12f8b89:	mov    %rdx,0x10(%rax)
 12f8b8d:	mov    0x68(%rbx),%rdx
 12f8b91:	mov    %rdx,0x18(%rax)
 12f8b95:	mov    0x70(%rbx),%rdx
 12f8b99:	mov    %rdx,0x20(%rax)
 12f8b9d:	mov    0x78(%rbx),%rdx
 12f8ba1:	mov    %rdx,0x28(%rax)
 12f8ba5:	mov    0x80(%rbx),%rdx
 12f8bac:	mov    %rdx,0x30(%rax)
 12f8bb0:	mov    0x88(%rbx),%rdx
 12f8bb7:	mov    %rdx,0x38(%rax)
 12f8bbb:	mov    0x90(%rbx),%rdx
 12f8bc2:	mov    %rdx,0x40(%rax)
 12f8bc6:	mov    0x98(%rbx),%rdx
 12f8bcd:	mov    %rdx,0x48(%rax)
 12f8bd1:	mov    0xa0(%rbx),%rdx
 12f8bd8:	mov    %rdx,0x50(%rax)
 12f8bdc:	mov    0xa8(%rbx),%rdx
 12f8be3:	mov    %rdx,0x58(%rax)
 12f8be7:	mov    0xb0(%rbx),%rdx
 12f8bee:	mov    %rdx,0x60(%rax)
 12f8bf2:	mov    0xb8(%rbx),%rdx
 12f8bf9:	mov    %rdx,0x68(%rax)
 12f8bfd:	mov    0xc0(%rbx),%rdx
 12f8c04:	mov    %rdx,0x70(%rax)
 12f8c08:	mov    0xc8(%rbx),%rdx
 12f8c0f:	mov    %rdx,0x78(%rax)
 12f8c13:	mov    -0x90(%rbp),%rax
 12f8c1a:	mov    %rax,0x50(%rbx)
 12f8c1e:	mov    -0x88(%rbp),%rax
 12f8c25:	mov    %rax,0x58(%rbx)
 12f8c29:	mov    -0x80(%rbp),%rax
 12f8c2d:	mov    %rax,0x60(%rbx)
 12f8c31:	mov    -0x78(%rbp),%rax
 12f8c35:	mov    %rax,0x68(%rbx)
 12f8c39:	mov    -0x70(%rbp),%rax
 12f8c3d:	mov    %rax,0x70(%rbx)
 12f8c41:	mov    -0x68(%rbp),%rax
 12f8c45:	mov    %rax,0x78(%rbx)
 12f8c49:	mov    -0x60(%rbp),%rax
 12f8c4d:	mov    %rax,0x80(%rbx)
 12f8c54:	mov    -0x58(%rbp),%rax
 12f8c58:	mov    %rax,0x88(%rbx)
 12f8c5f:	mov    -0x50(%rbp),%rax
 12f8c63:	mov    %rax,0x90(%rbx)
 12f8c6a:	mov    -0x48(%rbp),%rax
 12f8c6e:	mov    %rax,0x98(%rbx)
 12f8c75:	mov    -0x40(%rbp),%rax
 12f8c79:	mov    %rax,0xa0(%rbx)
 12f8c80:	mov    -0x38(%rbp),%rax
 12f8c84:	mov    %rax,0xa8(%rbx)
 12f8c8b:	mov    -0x30(%rbp),%rax
 12f8c8f:	mov    %rax,0xb0(%rbx)
 12f8c96:	mov    -0x28(%rbp),%rax
 12f8c9a:	mov    %rax,0xb8(%rbx)
 12f8ca1:	mov    -0x20(%rbp),%rax
 12f8ca5:	mov    %rax,0xc0(%rbx)
 12f8cac:	mov    -0x18(%rbp),%rax
 12f8cb0:	mov    %rax,0xc8(%rbx)
 12f8cb7:	mov    $0x1,%eax
 12f8cbc:	sub    $0xffffffffffffff80,%rsp
 12f8cc0:	pop    %rbx
 12f8cc1:	pop    %r12
 12f8cc3:	pop    %rbp
 12f8cc4:	retq   
 12f8cc5:	nopl   (%rax)
 12f8cc8:	mov    0x28(%r12),%rax
 12f8ccd:	add    $0x81,%rsi
 12f8cd4:	mov    0x20(%r12),%rdi
 12f8cd9:	mov    0x90(%rax),%rax
 12f8ce0:	mov    %rsi,0x18(%r12)
 12f8ce5:	shl    $0x7,%rsi
 12f8ce9:	callq  *%rax
 12f8ceb:	test   %rax,%rax
 12f8cee:	mov    %rax,0x20(%r12)
 12f8cf3:	je     12f8d6d <my_coll_parser_scan_shift_sequence+0x35d>
 12f8cf5:	mov    0x10(%r12),%rsi
 12f8cfa:	jmpq   12f8b66 <my_coll_parser_scan_shift_sequence+0x156>
 12f8cff:	mov    %rax,0x88(%rbx)
 12f8d06:	mov    0x28(%rbx),%rax
 12f8d0a:	mov    %r12,%rdi
 12f8d0d:	mov    %rax,(%rbx)
 12f8d10:	mov    0x30(%rbx),%rax
 12f8d14:	mov    %rax,0x8(%rbx)
 12f8d18:	mov    0x38(%rbx),%rax
 12f8d1c:	mov    %rax,0x10(%rbx)
 12f8d20:	mov    0x40(%rbx),%rax
 12f8d24:	mov    %rax,0x18(%rbx)
 12f8d28:	mov    0x48(%rbx),%rax
 12f8d2c:	mov    %rax,0x20(%rbx)
 12f8d30:	callq  12f7c10 <my_coll_lexem_next>
 12f8d35:	cmpl   $0x5,(%rbx)
 12f8d38:	jne    12f8b4a <my_coll_parser_scan_shift_sequence+0x13a>
 12f8d3e:	cmpq   $0x0,0x88(%rbx)
 12f8d46:	movslq 0x24(%rbx),%rax
 12f8d4a:	je     12f8cff <my_coll_parser_scan_shift_sequence+0x2ef>
 12f8d4c:	lea    0xd8(%rbx),%rdi
 12f8d53:	lea    0x2c06f6(%rip),%rcx        # 15b9450 <_ZTSN3THD17Attachable_trx_rwE+0x750>
 12f8d5a:	lea    0x547b55(%rip),%rdx        # 18408b6 <t_ctype+0x1416>
 12f8d61:	mov    $0x80,%esi
 12f8d66:	xor    %eax,%eax
 12f8d68:	callq  1313550 <my_snprintf>
 12f8d6d:	xor    %eax,%eax
 12f8d6f:	sub    $0xffffffffffffff80,%rsp
 12f8d73:	pop    %rbx
 12f8d74:	pop    %r12
 12f8d76:	pop    %rbp
 12f8d77:	retq   
 12f8d78:	nopl   0x0(%rax,%rax,1)
 12f8d80:	mov    0x28(%rbx),%rax
 12f8d84:	lea    0x28(%rbx),%r12
 12f8d88:	mov    %r12,%rdi
 12f8d8b:	mov    %rax,(%rbx)
 12f8d8e:	mov    0x30(%rbx),%rax
 12f8d92:	mov    %rax,0x8(%rbx)
 12f8d96:	mov    0x38(%rbx),%rax
 12f8d9a:	mov    %rax,0x10(%rbx)
 12f8d9e:	mov    0x40(%rbx),%rax
 12f8da2:	mov    %rax,0x18(%rbx)
 12f8da6:	mov    0x48(%rbx),%rax
 12f8daa:	mov    %rax,0x20(%rbx)
 12f8dae:	callq  12f7c10 <my_coll_lexem_next>
 12f8db3:	cmpl   $0x5,(%rbx)
 12f8db6:	movb   $0x1,0xc8(%rbx)
 12f8dbd:	je     12f8d3e <my_coll_parser_scan_shift_sequence+0x32e>
 12f8dc3:	lea    0xd8(%rbx),%rdi
 12f8dca:	lea    0x547acf(%rip),%rcx        # 18408a0 <t_ctype+0x1400>
 12f8dd1:	lea    0x547ad2(%rip),%rdx        # 18408aa <t_ctype+0x140a>
 12f8dd8:	mov    $0x80,%esi
 12f8ddd:	xor    %eax,%eax
 12f8ddf:	callq  1313550 <my_snprintf>
 12f8de4:	xor    %eax,%eax
 12f8de6:	jmp    12f8d6f <my_coll_parser_scan_shift_sequence+0x35f>
 12f8de8:	nopl   0x0(%rax,%rax,1)
 12f8df0:	xor    %ecx,%ecx
 12f8df2:	add    $0x2,%rdi
 12f8df6:	sub    $0x2,%edx
 12f8df9:	mov    %cx,-0x2(%rdi)
 12f8dfd:	test   $0x4,%dil
 12f8e01:	je     12f8a4b <my_coll_parser_scan_shift_sequence+0x3b>
 12f8e07:	nopw   0x0(%rax,%rax,1)
 12f8e10:	movl   $0x0,(%rdi)
 12f8e16:	sub    $0x4,%edx
 12f8e19:	add    $0x4,%rdi
 12f8e1d:	jmpq   12f8a4b <my_coll_parser_scan_shift_sequence+0x3b>
 12f8e22:	nopw   0x0(%rax,%rax,1)
 12f8e28:	movb   $0x0,0x80(%rbx)
 12f8e2f:	lea    0x81(%rbx),%rdi
 12f8e36:	mov    $0x2f,%dl
 12f8e38:	jmpq   12f8a37 <my_coll_parser_scan_shift_sequence+0x27>
 12f8e3d:	nopl   (%rax)
 12f8e40:	mov    0x28(%rbx),%rax
 12f8e44:	lea    0x28(%rbx),%rdi
 12f8e48:	mov    %rax,(%rbx)
 12f8e4b:	mov    0x30(%rbx),%rax
 12f8e4f:	mov    %rax,0x8(%rbx)
 12f8e53:	mov    0x38(%rbx),%rax
 12f8e57:	mov    %rax,0x10(%rbx)
 12f8e5b:	mov    0x40(%rbx),%rax
 12f8e5f:	mov    %rax,0x18(%rbx)
 12f8e63:	mov    0x48(%rbx),%rax
 12f8e67:	mov    %rax,0x20(%rbx)
 12f8e6b:	callq  12f7c10 <my_coll_lexem_next>
 12f8e70:	lea    0x50(%rbx),%rsi
 12f8e74:	lea    0x547a56(%rip),%rdx        # 18408d1 <t_ctype+0x1431>
 12f8e7b:	mov    %rbx,%rdi
 12f8e7e:	callq  12f86e0 <my_coll_parser_scan_character_list.constprop.25>
 12f8e83:	test   %eax,%eax
 12f8e85:	jne    12f8b4a <my_coll_parser_scan_shift_sequence+0x13a>
 12f8e8b:	jmpq   12f8d6d <my_coll_parser_scan_shift_sequence+0x35d>
