// TC_OUT channel_get@@Base,0x20d0a0,0x20d0b7,0x38(%r14)
// TC_OUT channel_get@@Base,0x20d0d8,0x20d134,0x98(%r14)
// TC_OUT channel_get@@Base,0x20d160,0x20d1a3,0x50(%rbx),0x8(0x50(%rbx))
// TC_OUT channel_get@@Base,0x20d17f,0x20d1b8,0x50(%rbx),0x8(0x50(%rbx))
// TC_OUT channel_get@@Base,0x20d160,0x20d16b,0x50(%rbx),0x8(0x50(%rbx))
000000000020ca40 <channel_get@@Base>:
  20ca40:	movslq %esi,%rsi
  20ca43:	push   %rbx
  20ca44:	lea    (%rsi,%rsi,4),%rax
  20ca48:	lea    (%rax,%rax,4),%rax
  20ca4c:	lea    (%rdi,%rax,8),%rdx
  20ca50:	mov    0x38(%rdx),%rdi
  20ca54:	test   %rdi,%rdi
  20ca57:	je     20ca90 <channel_get@@Base+0x50>
  20ca59:	mov    0x10(%rdi),%rax
  20ca5d:	mov    (%rdi),%rbx
  20ca60:	mov    %rax,0x38(%rdx)
  20ca64:	mov    0x10(%rdi),%rcx
  20ca68:	test   %rcx,%rcx
  20ca6b:	je     20ca80 <channel_get@@Base+0x40>
  20ca6d:	movq   $0x0,0x18(%rcx)
  20ca75:	callq  11c7f0 <vim_free@@Base>
  20ca7a:	mov    %rbx,%rax
  20ca7d:	pop    %rbx
  20ca7e:	retq   
  20ca7f:	nop
  20ca80:	movq   $0x0,0x40(%rdx)
  20ca88:	jmp    20ca75 <channel_get@@Base+0x35>
  20ca8a:	nopw   0x0(%rax,%rax,1)
  20ca90:	xor    %ebx,%ebx
  20ca92:	jmp    20ca7a <channel_get@@Base+0x3a>
  20ca94:	xchg   %ax,%ax
  20ca96:	nopw   %cs:0x0(%rax,%rax,1)
  20caa0:	push   %r15
  20caa2:	push   %r14
  20caa4:	xor    %r15d,%r15d
  20caa7:	push   %r13
  20caa9:	push   %r12
  20caab:	movslq %esi,%r12
  20caae:	push   %rbp
  20caaf:	push   %rbx
  20cab0:	sub    $0x78,%rsp
  20cab4:	mov    %fs:0x28,%rax
  20cabd:	mov    %rax,0x68(%rsp)
  20cac2:	xor    %eax,%eax
  20cac4:	lea    (%r12,%r12,4),%rax
  20cac8:	lea    (%rax,%rax,4),%rbp
  20cacc:	shl    $0x3,%rbp
  20cad0:	lea    (%rdi,%rbp,1),%r14
  20cad4:	cmpq   $0x0,0x38(%r14)
  20cad9:	je     20cb67 <channel_get@@Base+0x127>
  20cadf:	mov    %r12d,%esi
  20cae2:	mov    %rdi,%rbx
  20cae5:	lea    0x10(%rsp),%r15
  20caea:	callq  20ca40 <channel_get@@Base>
  20caef:	xor    %edx,%edx
  20caf1:	cmpl   $0x3,0x1c(%r14)
  20caf6:	mov    %rax,0x30(%rsp)
  20cafb:	lea    0x30(%rsp),%rdi
  20cb00:	lea    0x309(%rip),%rax        # 20ce10 <channel_get@@Base+0x3d0>
  20cb07:	mov    %r15,%rsi
  20cb0a:	movl   $0x0,0x40(%rsp)
  20cb12:	mov    %rbx,0x50(%rsp)
  20cb17:	mov    %r12,%r13
  20cb1a:	mov    %rax,0x48(%rsp)
  20cb1f:	mov    %r12d,0x58(%rsp)
  20cb24:	sete   %dl
  20cb27:	callq  213680 <json_decode@@Base>
  20cb2c:	cmp    $0x1,%eax
  20cb2f:	mov    %eax,%r10d
  20cb32:	je     20cbe0 <channel_get@@Base+0x1a0>
  20cb38:	cmp    $0x2,%eax
  20cb3b:	je     20cc30 <channel_get@@Base+0x1f0>
  20cb41:	test   %r10d,%r10d
  20cb44:	je     20cbb0 <channel_get@@Base+0x170>
  20cb46:	movslq 0x40(%rsp),%rdx
  20cb4b:	mov    0x30(%rsp),%rdi
  20cb50:	xor    %r15d,%r15d
  20cb53:	mov    %rdx,%rax
  20cb56:	add    %rdi,%rdx
  20cb59:	cmpb   $0x0,(%rdx)
  20cb5c:	jne    20cd40 <channel_get@@Base+0x300>
  20cb62:	callq  11c7f0 <vim_free@@Base>
  20cb67:	mov    0x68(%rsp),%rcx
  20cb6c:	xor    %fs:0x28,%rcx
  20cb75:	mov    %r15d,%eax
  20cb78:	jne    20cdfc <channel_get@@Base+0x3bc>
  20cb7e:	add    $0x78,%rsp
  20cb82:	pop    %rbx
  20cb83:	pop    %rbp
  20cb84:	pop    %r12
  20cb86:	pop    %r13
  20cb88:	pop    %r14
  20cb8a:	pop    %r15
  20cb8c:	retq   
  20cb8d:	nopl   (%rax)
  20cb90:	mov    0x70(%r14),%rax
  20cb94:	cmp    %rax,0x28(%rsp)
  20cb99:	jle    20cda6 <channel_get@@Base+0x366>
  20cb9f:	nop
  20cba0:	lea    (%r12,%r12,4),%rax
  20cba4:	lea    (%rax,%rax,4),%rax
  20cba8:	movl   $0x0,0x64(%rbx,%rax,8)
  20cbb0:	lea    0x2dba1(%rip),%rsi        # 23a758 <_IO_stdin_used@@Base+0x24198>
  20cbb7:	mov    %rbx,%rdi
  20cbba:	xor    %r15d,%r15d
  20cbbd:	callq  20b010 <netbeans_gutter_click@@Base+0x190>
  20cbc2:	lea    (%r12,%r12,4),%rax
  20cbc6:	mov    0x30(%rsp),%rdi
  20cbcb:	lea    (%rax,%rax,4),%rax
  20cbcf:	movl   $0x0,0x64(%rbx,%rax,8)
  20cbd7:	jmpq   20cb62 <channel_get@@Base+0x122>
  20cbdc:	nopl   0x0(%rax)
  20cbe0:	cmpl   $0x5,0x10(%rsp)
  20cbe5:	je     20cca0 <channel_get@@Base+0x260>
  20cbeb:	lea    0x2daee(%rip),%rsi        # 23a6e0 <_IO_stdin_used@@Base+0x24120>
  20cbf2:	mov    %rbx,%rdi
  20cbf5:	mov    %eax,0xc(%rsp)
  20cbf9:	callq  20b010 <netbeans_gutter_click@@Base+0x190>
  20cbfe:	mov    0xc(%rsp),%r10d
  20cc03:	mov    %r15,%rdi
  20cc06:	mov    %r10d,0xc(%rsp)
  20cc0b:	callq  87b20 <clear_tv@@Base>
  20cc10:	mov    0xc(%rsp),%r10d
  20cc15:	lea    (%r12,%r12,4),%rax
  20cc19:	lea    (%rax,%rax,4),%rax
  20cc1d:	movl   $0x0,0x64(%rbx,%rax,8)
  20cc25:	jmpq   20cb46 <channel_get@@Base+0x106>
  20cc2a:	nopw   0x0(%rax,%rax,1)
  20cc30:	mov    0x64(%r14),%eax
  20cc34:	mov    %r10d,0xc(%rsp)
  20cc39:	test   %eax,%eax
  20cc3b:	jne    20cd80 <channel_get@@Base+0x340>
  20cc41:	lea    0x2dae8(%rip),%rsi        # 23a730 <_IO_stdin_used@@Base+0x24170>
  20cc48:	mov    %rbx,%rdi
  20cc4b:	callq  20be30 <ch_log@@Base>
  20cc50:	lea    0x68(%rbx,%rbp,1),%rdi
  20cc55:	xor    %esi,%esi
  20cc57:	movl   $0x1,0x64(%r14)
  20cc5f:	movl   $0x0,0x40(%rsp)
  20cc67:	callq  4edf8 <_init@@Base+0x208>
  20cc6c:	mov    0x70(%r14),%rax
  20cc70:	mov    0xc(%rsp),%r10d
  20cc75:	lea    0x186a0(%rax),%rdx
  20cc7c:	cmp    $0xf4240,%rdx
  20cc83:	jle    20cdd0 <channel_get@@Base+0x390>
  20cc89:	sub    $0xdbba0,%rax
  20cc8f:	addq   $0x1,0x68(%r14)
  20cc94:	mov    %rax,0x70(%r14)
  20cc98:	jmpq   20cb46 <channel_get@@Base+0x106>
  20cc9d:	nopl   (%rax)
  20cca0:	mov    0x18(%rsp),%rax
  20cca5:	mov    0x14(%rax),%edx
  20cca8:	cmp    $0x1,%edx
  20ccab:	jle    20cd20 <channel_get@@Base+0x2e0>
  20ccad:	mov    $0x18,%edi
  20ccb2:	mov    %r10d,0xc(%rsp)
  20ccb7:	callq  121d10 <alloc@@Base>
  20ccbc:	test   %rax,%rax
  20ccbf:	mov    %rax,%rbp
  20ccc2:	mov    0xc(%rsp),%r10d
  20ccc7:	je     20cc03 <channel_get@@Base+0x1c3>
  20cccd:	callq  7c0b0 <alloc_tv@@Base>
  20ccd2:	test   %rax,%rax
  20ccd5:	mov    %rax,0x0(%rbp)
  20ccd9:	mov    0xc(%rsp),%r10d
  20ccde:	je     20cde2 <channel_get@@Base+0x3a2>
  20cce4:	mov    0x18(%rsp),%rdi
  20cce9:	mov    0x10(%rsp),%rsi
  20ccee:	mov    %rdi,0x8(%rax)
  20ccf2:	mov    %rsi,(%rax)
  20ccf5:	mov    0x58(%r14),%rax
  20ccf9:	mov    %rax,0x10(%rbp)
  20ccfd:	mov    %rbp,0x58(%r14)
  20cd01:	mov    0x10(%rbp),%rax
  20cd05:	movq   $0x0,0x8(%rbp)
  20cd0d:	test   %rax,%rax
  20cd10:	je     20cdd9 <channel_get@@Base+0x399>
  20cd16:	mov    %rbp,0x8(%rax)
  20cd1a:	jmpq   20cc15 <channel_get@@Base+0x1d5>
  20cd1f:	nop
  20cd20:	lea    0x2d9e1(%rip),%rsi        # 23a708 <_IO_stdin_used@@Base+0x24148>
  20cd27:	mov    %rbx,%rdi
  20cd2a:	mov    %r10d,0xc(%rsp)
  20cd2f:	callq  20b150 <netbeans_gutter_click@@Base+0x2d0>
  20cd34:	mov    0xc(%rsp),%r10d
  20cd39:	jmpq   20cc03 <channel_get@@Base+0x1c3>
  20cd3e:	xchg   %ax,%ax
  20cd40:	mov    0x38(%rsp),%rcx
  20cd45:	xor    %r9d,%r9d
  20cd48:	mov    $0x1,%r8d
  20cd4e:	mov    %r13d,%esi
  20cd51:	mov    %r10d,0xc(%rsp)
  20cd56:	xor    %r15d,%r15d
  20cd59:	sub    %rdi,%rcx
  20cd5c:	mov    %rbx,%rdi
  20cd5f:	sub    %eax,%ecx
  20cd61:	callq  20b880 <netbeans_gutter_click@@Base+0xa00>
  20cd66:	mov    0xc(%rsp),%r10d
  20cd6b:	mov    0x30(%rsp),%rdi
  20cd70:	cmp    $0x2,%r10d
  20cd74:	setne  %r15b
  20cd78:	jmpq   20cb62 <channel_get@@Base+0x122>
  20cd7d:	nopl   (%rax)
  20cd80:	lea    0x20(%rsp),%rdi
  20cd85:	xor    %esi,%esi
  20cd87:	callq  4edf8 <_init@@Base+0x208>
  20cd8c:	mov    0x68(%r14),%rax
  20cd90:	cmp    %rax,0x20(%rsp)
  20cd95:	jg     20cba0 <channel_get@@Base+0x160>
  20cd9b:	mov    0xc(%rsp),%r10d
  20cda0:	je     20cb90 <channel_get@@Base+0x150>
  20cda6:	lea    0x2d9d3(%rip),%rsi        # 23a780 <_IO_stdin_used@@Base+0x241c0>
  20cdad:	mov    %rbx,%rdi
  20cdb0:	mov    %r10d,0xc(%rsp)
  20cdb5:	movl   $0x0,0x40(%rsp)
  20cdbd:	callq  20be30 <ch_log@@Base>
  20cdc2:	mov    0xc(%rsp),%r10d
  20cdc7:	jmpq   20cb46 <channel_get@@Base+0x106>
  20cdcc:	nopl   0x0(%rax)
  20cdd0:	mov    %rdx,0x70(%r14)
  20cdd4:	jmpq   20cb46 <channel_get@@Base+0x106>
  20cdd9:	mov    %rbp,0x50(%r14)
  20cddd:	jmpq   20cc15 <channel_get@@Base+0x1d5>
  20cde2:	mov    %rbp,%rdi
  20cde5:	callq  11c7f0 <vim_free@@Base>
  20cdea:	mov    %r15,%rdi
  20cded:	callq  87b20 <clear_tv@@Base>
  20cdf2:	mov    0xc(%rsp),%r10d
  20cdf7:	jmpq   20cc15 <channel_get@@Base+0x1d5>
  20cdfc:	callq  4ed90 <_init@@Base+0x1a0>
  20ce01:	nopl   0x0(%rax,%rax,1)
  20ce06:	nopw   %cs:0x0(%rax,%rax,1)
  20ce10:	push   %r14
  20ce12:	push   %r13
  20ce14:	push   %r12
  20ce16:	push   %rbp
  20ce17:	mov    %rdi,%rbp
  20ce1a:	push   %rbx
  20ce1b:	mov    0x28(%rdi),%esi
  20ce1e:	mov    0x20(%rdi),%rdi
  20ce22:	callq  20ca40 <channel_get@@Base>
  20ce27:	test   %rax,%rax
  20ce2a:	je     20cec0 <channel_get@@Base+0x480>
  20ce30:	mov    0x0(%rbp),%rdi
  20ce34:	mov    0x8(%rbp),%rbx
  20ce38:	mov    %rax,%r12
  20ce3b:	sub    %rdi,%rbx
  20ce3e:	sub    0x10(%rbp),%ebx
  20ce41:	test   %ebx,%ebx
  20ce43:	jle    20ceb8 <channel_get@@Base+0x478>
  20ce45:	mov    %rax,%rdi
  20ce48:	callq  4ed80 <_init@@Base+0x190>
  20ce4d:	lea    0x1(%rbx,%rax,1),%edi
  20ce51:	mov    %rax,%r14
  20ce54:	callq  121d10 <alloc@@Base>
  20ce59:	test   %rax,%rax
  20ce5c:	mov    %rax,%r13
  20ce5f:	je     20ced0 <channel_get@@Base+0x490>
  20ce61:	movslq 0x10(%rbp),%rsi
  20ce65:	movslq %ebx,%rbx
  20ce68:	mov    %rax,%rdi
  20ce6b:	add    0x0(%rbp),%rsi
  20ce6f:	mov    %rbx,%rdx
  20ce72:	callq  4f0d0 <_init@@Base+0x4e0>
  20ce77:	lea    0x1(%r14),%edx
  20ce7b:	lea    0x0(%r13,%rbx,1),%rdi
  20ce80:	mov    %r12,%rsi
  20ce83:	movslq %edx,%rdx
  20ce86:	callq  4f0d0 <_init@@Base+0x4e0>
  20ce8b:	mov    %r12,%rdi
  20ce8e:	callq  11c7f0 <vim_free@@Base>
  20ce93:	mov    0x0(%rbp),%rdi
  20ce97:	callq  11c7f0 <vim_free@@Base>
  20ce9c:	mov    %r13,0x0(%rbp)
  20cea0:	movl   $0x0,0x10(%rbp)
  20cea7:	mov    $0x1,%eax
  20ceac:	pop    %rbx
  20cead:	pop    %rbp
  20ceae:	pop    %r12
  20ceb0:	pop    %r13
  20ceb2:	pop    %r14
  20ceb4:	retq   
  20ceb5:	nopl   (%rax)
  20ceb8:	mov    %rax,%r13
  20cebb:	jmp    20ce97 <channel_get@@Base+0x457>
  20cebd:	nopl   (%rax)
  20cec0:	pop    %rbx
  20cec1:	xor    %eax,%eax
  20cec3:	pop    %rbp
  20cec4:	pop    %r12
  20cec6:	pop    %r13
  20cec8:	pop    %r14
  20ceca:	retq   
  20cecb:	nopl   0x0(%rax,%rax,1)
  20ced0:	mov    %r12,%rdi
  20ced3:	callq  11c7f0 <vim_free@@Base>
  20ced8:	xor    %eax,%eax
  20ceda:	jmp    20ceac <channel_get@@Base+0x46c>
  20cedc:	nopl   0x0(%rax)
  20cee0:	push   %r15
  20cee2:	push   %r14
  20cee4:	push   %r13
  20cee6:	push   %r12
  20cee8:	push   %rbp
  20cee9:	movslq %esi,%rbp
  20ceec:	push   %rbx
  20ceed:	lea    0x0(%rbp,%rbp,4),%rax
  20cef2:	sub    $0x8,%rsp
  20cef6:	lea    (%rax,%rax,4),%rax
  20cefa:	mov    0x38(%rdi,%rax,8),%rdx
  20ceff:	test   %rdx,%rdx
  20cf02:	je     20cfe0 <channel_get@@Base+0x5a0>
  20cf08:	mov    0x10(%rdx),%rax
  20cf0c:	test   %rax,%rax
  20cf0f:	je     20cfe0 <channel_get@@Base+0x5a0>
  20cf15:	xor    %ebx,%ebx
  20cf17:	jmp    20cf27 <channel_get@@Base+0x4e7>
  20cf19:	nopl   0x0(%rax)
  20cf20:	mov    %rax,%rdx
  20cf23:	mov    0x10(%rax),%rax
  20cf27:	add    0x8(%rdx),%rbx
  20cf2b:	test   %rax,%rax
  20cf2e:	mov    %rbx,%r12
  20cf31:	jne    20cf20 <channel_get@@Base+0x4e0>
  20cf33:	mov    %rdi,%r14
  20cf36:	lea    0x1(%rbx),%rdi
  20cf3a:	mov    %esi,%r15d
  20cf3d:	mov    $0x1,%esi
  20cf42:	callq  11e8f0 <lalloc@@Base>
  20cf47:	test   %rax,%rax
  20cf4a:	mov    %rax,%r13
  20cf4d:	je     20cfc7 <channel_get@@Base+0x587>
  20cf4f:	lea    0x0(%rbp,%rbp,4),%rax
  20cf54:	mov    %r13,%rcx
  20cf57:	lea    (%rax,%rax,4),%rax
  20cf5b:	mov    0x38(%r14,%rax,8),%rbp
  20cf60:	test   %rbp,%rbp
  20cf63:	je     20cf88 <channel_get@@Base+0x548>
  20cf65:	nopl   (%rax)
  20cf68:	mov    0x8(%rbp),%rdx
  20cf6c:	mov    0x0(%rbp),%rsi
  20cf70:	mov    %rcx,%rdi
  20cf73:	callq  4f0d0 <_init@@Base+0x4e0>
  20cf78:	mov    %rax,%rcx
  20cf7b:	add    0x8(%rbp),%rcx
  20cf7f:	mov    0x10(%rbp),%rbp
  20cf83:	test   %rbp,%rbp
  20cf86:	jne    20cf68 <channel_get@@Base+0x528>
  20cf88:	movb   $0x0,(%rcx)
  20cf8b:	nopl   0x0(%rax,%rax,1)
  20cf90:	mov    %r15d,%esi
  20cf93:	mov    %r14,%rdi
  20cf96:	callq  20ca40 <channel_get@@Base>
  20cf9b:	mov    %rax,%rbp
  20cf9e:	mov    %rax,%rdi
  20cfa1:	callq  11c7f0 <vim_free@@Base>
  20cfa6:	test   %rbp,%rbp
  20cfa9:	jne    20cf90 <channel_get@@Base+0x550>
  20cfab:	test   %r12,%r12
  20cfae:	je     20cfc7 <channel_get@@Base+0x587>
  20cfb0:	sub    $0x1,%rbx
  20cfb4:	cmpb   $0x0,0x0(%r13,%rbx,1)
  20cfba:	jne    20cfc2 <channel_get@@Base+0x582>
  20cfbc:	movb   $0xa,0x0(%r13,%rbx,1)
  20cfc2:	test   %rbx,%rbx
  20cfc5:	jne    20cfb0 <channel_get@@Base+0x570>
  20cfc7:	add    $0x8,%rsp
  20cfcb:	mov    %r13,%rax
  20cfce:	pop    %rbx
  20cfcf:	pop    %rbp
  20cfd0:	pop    %r12
  20cfd2:	pop    %r13
  20cfd4:	pop    %r14
  20cfd6:	pop    %r15
  20cfd8:	retq   
  20cfd9:	nopl   0x0(%rax)
  20cfe0:	add    $0x8,%rsp
  20cfe4:	pop    %rbx
  20cfe5:	pop    %rbp
  20cfe6:	pop    %r12
  20cfe8:	pop    %r13
  20cfea:	pop    %r14
  20cfec:	pop    %r15
  20cfee:	jmpq   20ca40 <channel_get@@Base>
  20cff3:	nopl   (%rax)
  20cff6:	nopw   %cs:0x0(%rax,%rax,1)
  20d000:	push   %r13
  20d002:	push   %r12
  20d004:	lea    0x2d21a(%rip),%r13        # 23a225 <_IO_stdin_used@@Base+0x23c65>
  20d00b:	push   %rbp
  20d00c:	push   %rbx
  20d00d:	mov    %rdi,%rbp
  20d010:	mov    %esi,%r12d
  20d013:	sub    $0x8,%rsp
  20d017:	jmp    20d036 <channel_get@@Base+0x5f6>
  20d019:	nopl   0x0(%rax)
  20d020:	mov    %rbp,%rdi
  20d023:	mov    %rbx,%rdx
  20d026:	mov    %r13,%rsi
  20d029:	callq  20bfe0 <ch_logs@@Base>
  20d02e:	mov    %rbx,%rdi
  20d031:	callq  11c7f0 <vim_free@@Base>
  20d036:	mov    %r12d,%esi
  20d039:	mov    %rbp,%rdi
  20d03c:	callq  20ca40 <channel_get@@Base>
  20d041:	test   %rax,%rax
  20d044:	mov    %rax,%rbx
  20d047:	jne    20d020 <channel_get@@Base+0x5e0>
  20d049:	add    $0x8,%rsp
  20d04d:	pop    %rbx
  20d04e:	pop    %rbp
  20d04f:	pop    %r12
  20d051:	pop    %r13
  20d053:	retq   
  20d054:	xchg   %ax,%ax
  20d056:	nopw   %cs:0x0(%rax,%rax,1)
  20d060:	push   %r15
  20d062:	push   %r14
  20d064:	push   %r13
  20d066:	push   %r12
  20d068:	movslq %esi,%r12
  20d06b:	lea    (%r12,%r12,4),%rax
  20d06f:	push   %rbp
  20d070:	push   %rbx
  20d071:	mov    %rdi,%rbp
  20d074:	mov    %r12,%rbx
  20d077:	lea    (%rax,%rax,4),%rax
  20d07b:	sub    $0x8,%rsp
  20d07f:	shl    $0x3,%rax
  20d083:	lea    0x48(%rdi,%rax,1),%r13
  20d088:	lea    0x80(%rdi,%rax,1),%r15
  20d090:	add    %rdi,%rax
  20d093:	cmpq   $0x0,0x38(%rax)
  20d098:	mov    %rax,%r14
  20d09b:	je     20d0b9 <channel_get@@Base+0x679>
  20d09d:	nopl   (%rax)
  20d0a0:	mov    %ebx,%esi
  20d0a2:	mov    %rbp,%rdi
  20d0a5:	callq  20ca40 <channel_get@@Base>
  20d0aa:	mov    %rax,%rdi
  20d0ad:	callq  11c7f0 <vim_free@@Base>
  20d0b2:	cmpq   $0x0,0x38(%r14)
  20d0b7:	jne    20d0a0 <channel_get@@Base+0x660>
  20d0b9:	lea    (%r12,%r12,4),%rax
  20d0bd:	lea    (%rax,%rax,4),%rax
  20d0c1:	lea    0x0(%rbp,%rax,8),%r14
  20d0c6:	mov    0x98(%r14),%rbx
  20d0cd:	test   %rbx,%rbx
  20d0d0:	jne    20d10e <channel_get@@Base+0x6ce>
  20d0d2:	jmp    20d140 <channel_get@@Base+0x700>
  20d0d4:	nopl   0x0(%rax)
  20d0d8:	mov    %rdx,0x18(%rax)
  20d0dc:	mov    0x18(%rbx),%rdx
  20d0e0:	test   %rdx,%rdx
  20d0e3:	je     20d130 <channel_get@@Base+0x6f0>
  20d0e5:	mov    %rax,0x20(%rdx)
  20d0e9:	mov    (%rbx),%rdi
  20d0ec:	callq  11c7f0 <vim_free@@Base>
  20d0f1:	mov    0x8(%rbx),%rdi
  20d0f5:	callq  87b00 <partial_unref@@Base>
  20d0fa:	mov    %rbx,%rdi
  20d0fd:	callq  11c7f0 <vim_free@@Base>
  20d102:	mov    0x98(%r14),%rbx
  20d109:	test   %rbx,%rbx
  20d10c:	je     20d140 <channel_get@@Base+0x700>
  20d10e:	mov    0x20(%rbx),%rax
  20d112:	mov    0x18(%rbx),%rdx
  20d116:	test   %rax,%rax
  20d119:	jne    20d0d8 <channel_get@@Base+0x698>
  20d11b:	mov    %rdx,0x18(%r15)
  20d11f:	mov    0x18(%rbx),%rdx
  20d123:	test   %rdx,%rdx
  20d126:	jne    20d0e5 <channel_get@@Base+0x6a5>
  20d128:	nopl   0x0(%rax,%rax,1)
  20d130:	mov    %rax,0x20(%r15)
  20d134:	jmp    20d0e9 <channel_get@@Base+0x6a9>
  20d136:	nopw   %cs:0x0(%rax,%rax,1)
  20d140:	lea    (%r12,%r12,4),%rax
  20d144:	lea    (%rax,%rax,4),%rax
  20d148:	lea    0x0(%rbp,%rax,8),%rbx
  20d14d:	mov    0x50(%rbx),%rax
  20d151:	test   %rax,%rax
  20d154:	jne    20d17f <channel_get@@Base+0x73f>
  20d156:	jmp    20d1ba <channel_get@@Base+0x77a>
  20d158:	nopl   0x0(%rax,%rax,1)
  20d160:	mov    %rdx,0x8(%rax)
  20d164:	mov    0x8(%rdi),%rdx
  20d168:	test   %rdx,%rdx
  20d16b:	je     20d1a8 <channel_get@@Base+0x768>
  20d16d:	mov    %rax,0x10(%rdx)
  20d171:	callq  11c7f0 <vim_free@@Base>
  20d176:	mov    0x50(%rbx),%rax
  20d17a:	test   %rax,%rax
  20d17d:	je     20d1ba <channel_get@@Base+0x77a>
  20d17f:	mov    (%rax),%rdi
  20d182:	callq  8bcb0 <free_tv@@Base>
  20d187:	mov    0x50(%rbx),%rdi
  20d18b:	mov    0x10(%rdi),%rax
  20d18f:	mov    0x8(%rdi),%rdx
  20d193:	test   %rax,%rax
  20d196:	jne    20d160 <channel_get@@Base+0x720>
  20d198:	mov    %rdx,0x8(%r13)
  20d19c:	mov    0x8(%rdi),%rdx
  20d1a0:	test   %rdx,%rdx
  20d1a3:	jne    20d16d <channel_get@@Base+0x72d>
  20d1a5:	nopl   (%rax)
  20d1a8:	mov    %rax,0x10(%r13)
  20d1ac:	callq  11c7f0 <vim_free@@Base>
  20d1b1:	mov    0x50(%rbx),%rax
  20d1b5:	test   %rax,%rax
  20d1b8:	jne    20d17f <channel_get@@Base+0x73f>
  20d1ba:	lea    (%r12,%r12,4),%rax
  20d1be:	lea    (%rax,%rax,4),%rax
  20d1c2:	lea    0x0(%rbp,%rax,8),%rbx
  20d1c7:	mov    0xa8(%rbx),%rdi
  20d1ce:	callq  11c7f0 <vim_free@@Base>
  20d1d3:	mov    0xb0(%rbx),%rdi
  20d1da:	movq   $0x0,0xa8(%rbx)
  20d1e5:	callq  87b00 <partial_unref@@Base>
  20d1ea:	movq   $0x0,0xb0(%rbx)
  20d1f5:	add    $0x8,%rsp
  20d1f9:	pop    %rbx
  20d1fa:	pop    %rbp
  20d1fb:	pop    %r12
  20d1fd:	pop    %r13
  20d1ff:	pop    %r14
  20d201:	pop    %r15
  20d203:	retq   
  20d204:	xchg   %ax,%ax
  20d206:	nopw   %cs:0x0(%rax,%rax,1)
