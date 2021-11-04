// TC_OUT
00000000000a4f00 <do_sub@@Base>:
   a4f00:	push   %r15
   a4f02:	push   %r14
   a4f04:	push   %r13
   a4f06:	push   %r12
   a4f08:	push   %rbp
   a4f09:	push   %rbx
   a4f0a:	sub    $0x238,%rsp
   a4f11:	mov    %fs:0x28,%rax
   a4f1a:	mov    %rax,0x228(%rsp)
   a4f22:	xor    %eax,%eax
   a4f24:	mov    0x408e4d(%rip),%rax        # 4add78 <curbuf@@Base>
   a4f2b:	mov    %rdi,0x90(%rsp)
   a4f33:	mov    (%rdi),%rdi
   a4f36:	mov    (%rax),%rax
   a4f39:	mov    %rdi,0xc8(%rsp)
   a4f41:	mov    %rax,0xa0(%rsp)
   a4f49:	mov    0x4097c0(%rip),%rax        # 4ae710 <curwin@@Base>
   a4f50:	mov    0x38(%rax),%rcx
   a4f54:	mov    %rcx,0xb0(%rsp)
   a4f5c:	mov    0x40(%rax),%ecx
   a4f5f:	mov    0x44(%rax),%eax
   a4f62:	mov    %ecx,0xb8(%rsp)
   a4f69:	mov    %eax,0xac(%rsp)
   a4f70:	mov    0x408c5a(%rip),%eax        # 4adbd0 <global_busy@@Base>
   a4f76:	test   %eax,%eax
   a4f78:	mov    %eax,0x9c(%rsp)
   a4f7f:	je     a5162 <do_sub@@Base+0x262>
   a4f85:	mov    0x40a635(%rip),%eax        # 4af5c0 <sub_nsubs@@Base>
   a4f8b:	mov    %eax,0x9c(%rsp)
   a4f92:	mov    0x90(%rsp),%rax
   a4f9a:	xor    %ebp,%ebp
   a4f9c:	cmpl   $0x211,0x20(%rax)
   a4fa3:	mov    0x10(%rax),%rax
   a4fa7:	sete   %bpl
   a4fab:	add    $0x1,%ebp
   a4fae:	cmpb   $0x73,(%rax)
   a4fb1:	je     a5434 <do_sub@@Base+0x534>
   a4fb7:	mov    0x90(%rsp),%rax
   a4fbf:	mov    0x30(%rax),%r11d
   a4fc3:	test   %r11d,%r11d
   a4fc6:	jne    a517d <do_sub@@Base+0x27d>
   a4fcc:	mov    0x3fce05(%rip),%rax        # 4a1dd8 <current_funccal@@Base+0x4d0>
   a4fd3:	test   %rax,%rax
   a4fd6:	mov    %rax,0x20(%rsp)
   a4fdb:	je     a559f <do_sub@@Base+0x69f>
   a4fe1:	mov    0x409728(%rip),%rax        # 4ae710 <curwin@@Base>
   a4fe8:	mov    0xc8(%rsp),%rdi
   a4ff0:	cmpl   $0x7fffffff,0x48(%rax)
   a4ff7:	sete   %al
   a4ffa:	xor    %r12d,%r12d
   a4ffd:	movzbl %al,%eax
   a5000:	mov    %eax,0x98(%rsp)
   a5007:	movzbl (%rdi),%eax
   a500a:	cmp    $0x26,%al
   a500c:	je     a51a7 <do_sub@@Base+0x2a7>
   a5012:	mov    0x40a5cf(%rip),%r9d        # 4af5e8 <p_ed@@Base>
   a5019:	test   %r9d,%r9d
   a501c:	jne    a503d <do_sub@@Base+0x13d>
   a501e:	mov    0x40a1d3(%rip),%r8d        # 4af1f8 <p_gd@@Base>
   a5025:	xor    %edx,%edx
   a5027:	movl   $0x0,0x3fcd8b(%rip)        # 4a1dbc <current_funccal@@Base+0x4b4>
   a5031:	test   %r8d,%r8d
   a5034:	setne  %dl
   a5037:	mov    %edx,0x3fcd83(%rip)        # 4a1dc0 <current_funccal@@Base+0x4b8>
   a503d:	test   %al,%al
   a503f:	movl   $0x1,0x3e8c1f(%rip)        # 48dc68 <__data_start@@Base+0x4c68>
   a5049:	movl   $0x0,0x3fcd65(%rip)        # 4a1db8 <current_funccal@@Base+0x4b0>
   a5053:	movl   $0x0,0x3fcd57(%rip)        # 4a1db4 <current_funccal@@Base+0x4ac>
   a505d:	movl   $0x0,0x3fcd49(%rip)        # 4a1db0 <current_funccal@@Base+0x4a8>
   a5067:	movl   $0x0,0x3fcd3b(%rip)        # 4a1dac <current_funccal@@Base+0x4a4>
   a5071:	je     a6845 <do_sub@@Base+0x1945>
   a5077:	mov    0x3fcd2f(%rip),%ecx        # 4a1dac <current_funccal@@Base+0x4a4>
   a507d:	mov    0x3fcd2d(%rip),%edx        # 4a1db0 <current_funccal@@Base+0x4a8>
   a5083:	xor    %r15d,%r15d
   a5086:	mov    0x3fcd2c(%rip),%ebx        # 4a1db8 <current_funccal@@Base+0x4b0>
   a508c:	mov    0x3e8bd5(%rip),%r9d        # 48dc68 <__data_start@@Base+0x4c68>
   a5093:	xor    %r13d,%r13d
   a5096:	mov    0x3fcd17(%rip),%r10d        # 4a1db4 <current_funccal@@Base+0x4ac>
   a509d:	xor    %r14d,%r14d
   a50a0:	xor    %esi,%esi
   a50a2:	mov    %ecx,(%rsp)
   a50a5:	mov    %edx,0x8(%rsp)
   a50a9:	xor    %r11d,%r11d
   a50ac:	mov    0x3fccf6(%rip),%ecx        # 4a1da8 <current_funccal@@Base+0x4a0>
   a50b2:	mov    0x3fcd08(%rip),%edx        # 4a1dc0 <current_funccal@@Base+0x4b8>
   a50b8:	xor    %r8d,%r8d
   a50bb:	movb   $0x0,0xc(%rsp)
   a50c0:	movb   $0x0,0x18(%rsp)
   a50c5:	mov    %ecx,0x10(%rsp)
   a50c9:	mov    %edx,0xa8(%rsp)
   a50d0:	mov    0x3fcce6(%rip),%ecx        # 4a1dbc <current_funccal@@Base+0x4b4>
   a50d6:	jmp    a514f <do_sub@@Base+0x24f>
   a50d8:	nopl   0x0(%rax,%rax,1)
   a50e0:	cmp    $0x63,%al
   a50e2:	je     a5300 <do_sub@@Base+0x400>
   a50e8:	cmp    $0x6e,%al
   a50ea:	je     a5318 <do_sub@@Base+0x418>
   a50f0:	cmp    $0x65,%al
   a50f2:	je     a5330 <do_sub@@Base+0x430>
   a50f8:	cmp    $0x72,%al
   a50fa:	je     a5350 <do_sub@@Base+0x450>
   a5100:	cmp    $0x70,%al
   a5102:	je     a535a <do_sub@@Base+0x45a>
   a5108:	cmp    $0x23,%al
   a510a:	je     a53e8 <do_sub@@Base+0x4e8>
   a5110:	cmp    $0x6c,%al
   a5112:	je     a5405 <do_sub@@Base+0x505>
   a5118:	cmp    $0x69,%al
   a511a:	je     a5422 <do_sub@@Base+0x522>
   a5120:	cmp    $0x49,%al
   a5122:	jne    a536a <do_sub@@Base+0x46a>
   a5128:	mov    $0x1,%r15d
   a512e:	movl   $0x49,(%rsp)
   a5135:	nopl   (%rax)
   a5138:	add    $0x1,%rdi
   a513c:	mov    %rdi,0xc8(%rsp)
   a5144:	movzbl (%rdi),%eax
   a5147:	test   %al,%al
   a5149:	je     a536a <do_sub@@Base+0x46a>
   a514f:	cmp    $0x67,%al
   a5151:	jne    a50e0 <do_sub@@Base+0x1e0>
   a5153:	test   %edx,%edx
   a5155:	mov    $0x1,%esi
   a515a:	sete   %dl
   a515d:	movzbl %dl,%edx
   a5160:	jmp    a5138 <do_sub@@Base+0x238>
   a5162:	movq   $0x0,0x40a453(%rip)        # 4af5c0 <sub_nsubs@@Base>
   a516d:	movq   $0x0,0x40a2c8(%rip)        # 4af440 <sub_nlines@@Base>
   a5178:	jmpq   a4f92 <do_sub@@Base+0x92>
   a517d:	mov    0xc8(%rsp),%rdi
   a5185:	xor    %r12d,%r12d
   a5188:	movl   $0x0,0x98(%rsp)
   a5193:	movq   $0x0,0x20(%rsp)
   a519c:	movzbl (%rdi),%eax
   a519f:	cmp    $0x26,%al
   a51a1:	jne    a5012 <do_sub@@Base+0x112>
   a51a7:	lea    0x1(%rdi),%rdx
   a51ab:	mov    %rdx,0xc8(%rsp)
   a51b3:	movzbl 0x1(%rdi),%eax
   a51b7:	mov    %rdx,%rdi
   a51ba:	test   %al,%al
   a51bc:	jne    a5077 <do_sub@@Base+0x177>
   a51c2:	mov    0x3fcbf8(%rip),%eax        # 4a1dc0 <current_funccal@@Base+0x4b8>
   a51c8:	mov    %eax,0xa8(%rsp)
   a51cf:	mov    0x3fcbdf(%rip),%esi        # 4a1db4 <current_funccal@@Base+0x4ac>
   a51d5:	test   %esi,%esi
   a51d7:	jne    a55e3 <do_sub@@Base+0x6e3>
   a51dd:	mov    0x3fcbd9(%rip),%eax        # 4a1dbc <current_funccal@@Base+0x4b4>
   a51e3:	mov    %eax,0xbc(%rsp)
   a51ea:	callq  607e0 <skipwhite@@Base>
   a51ef:	mov    %rax,0xc8(%rsp)
   a51f7:	movzbl (%rax),%edx
   a51fa:	sub    $0x30,%edx
   a51fd:	cmp    $0x9,%edx
   a5200:	ja     a5254 <do_sub@@Base+0x354>
   a5202:	lea    0xc8(%rsp),%rdi
   a520a:	callq  60c70 <getdigits@@Base>
   a520f:	test   %rax,%rax
   a5212:	jle    a6700 <do_sub@@Base+0x1800>
   a5218:	mov    0x90(%rsp),%rcx
   a5220:	mov    0x48(%rcx),%rdx
   a5224:	lea    -0x1(%rax,%rdx,1),%rax
   a5229:	mov    %rdx,0x40(%rcx)
   a522d:	mov    0x408b44(%rip),%rdx        # 4add78 <curbuf@@Base>
   a5234:	mov    %rax,0x48(%rcx)
   a5238:	mov    (%rdx),%rdx
   a523b:	cmp    %rdx,%rax
   a523e:	jle    a524c <do_sub@@Base+0x34c>
   a5240:	mov    0x90(%rsp),%rax
   a5248:	mov    %rdx,0x48(%rax)
   a524c:	mov    0xc8(%rsp),%rax
   a5254:	mov    %rax,%rdi
   a5257:	callq  607e0 <skipwhite@@Base>
   a525c:	mov    %rax,0xc8(%rsp)
   a5264:	movzbl (%rax),%edx
   a5267:	test   %dl,%dl
   a5269:	je     a5274 <do_sub@@Base+0x374>
   a526b:	cmp    $0x22,%dl
   a526e:	jne    a55fd <do_sub@@Base+0x6fd>
   a5274:	mov    0x90(%rsp),%rax
   a527c:	mov    0x30(%rax),%ebx
   a527f:	test   %ebx,%ebx
   a5281:	jne    a55ba <do_sub@@Base+0x6ba>
   a5287:	mov    0x3fcb27(%rip),%eax        # 4a1db4 <current_funccal@@Base+0x4ac>
   a528d:	test   %eax,%eax
   a528f:	jne    a52a6 <do_sub@@Base+0x3a6>
   a5291:	mov    0x408ae0(%rip),%rax        # 4add78 <curbuf@@Base>
   a5298:	mov    0x14e0(%rax),%eax
   a529e:	test   %eax,%eax
   a52a0:	je     a67d1 <do_sub@@Base+0x18d1>
   a52a6:	lea    0xd0(%rsp),%rax
   a52ae:	mov    $0x20,%ecx
   a52b3:	mov    %ebp,%edx
   a52b5:	mov    $0x1,%esi
   a52ba:	mov    %r12,%rdi
   a52bd:	mov    %rax,%r8
   a52c0:	mov    %rax,0x30(%rsp)
   a52c5:	callq  192c70 <search_regcomp@@Base>
   a52ca:	test   %eax,%eax
   a52cc:	jne    a5640 <do_sub@@Base+0x740>
   a52d2:	mov    0x3e8990(%rip),%eax        # 48dc68 <__data_start@@Base+0x4c68>
   a52d8:	test   %eax,%eax
   a52da:	je     a55ba <do_sub@@Base+0x6ba>
   a52e0:	lea    0x3fb6e9(%rip),%rsi        # 4a09d0 <e_invcmd@@Base>
   a52e7:	xor    %edi,%edi
   a52e9:	mov    $0x5,%edx
   a52ee:	callq  4ed78 <_init@@Base+0x188>
   a52f3:	mov    %rax,%rdi
   a52f6:	callq  10d330 <emsg@@Base>
   a52fb:	jmpq   a55ba <do_sub@@Base+0x6ba>
   a5300:	test   %ecx,%ecx
   a5302:	mov    $0x1,%r8d
   a5308:	sete   %cl
   a530b:	movzbl %cl,%ecx
   a530e:	jmpq   a5138 <do_sub@@Base+0x238>
   a5313:	nopl   0x0(%rax,%rax,1)
   a5318:	mov    $0x1,%r11d
   a531e:	mov    $0x1,%r10d
   a5324:	jmpq   a5138 <do_sub@@Base+0x238>
   a5329:	nopl   0x0(%rax)
   a5330:	test   %r9d,%r9d
   a5333:	mov    $0x1,%r14d
   a5339:	sete   %r9b
   a533d:	movzbl %r9b,%r9d
   a5341:	jmpq   a5138 <do_sub@@Base+0x238>
   a5346:	nopw   %cs:0x0(%rax,%rax,1)
   a5350:	mov    $0x2,%ebp
   a5355:	jmpq   a5138 <do_sub@@Base+0x238>
   a535a:	mov    $0x1,%r13d
   a5360:	mov    $0x1,%ebx
   a5365:	jmpq   a5138 <do_sub@@Base+0x238>
   a536a:	test   %r8b,%r8b
   a536d:	jne    a6b89 <do_sub@@Base+0x1c89>
   a5373:	cmpb   $0x0,0x18(%rsp)
   a5378:	je     a5384 <do_sub@@Base+0x484>
   a537a:	mov    0x10(%rsp),%eax
   a537e:	mov    %eax,0x3fca24(%rip)        # 4a1da8 <current_funccal@@Base+0x4a0>
   a5384:	cmpb   $0x0,0xc(%rsp)
   a5389:	je     a5395 <do_sub@@Base+0x495>
   a538b:	mov    0x8(%rsp),%eax
   a538f:	mov    %eax,0x3fca1b(%rip)        # 4a1db0 <current_funccal@@Base+0x4a8>
   a5395:	test   %r11b,%r11b
   a5398:	je     a53a1 <do_sub@@Base+0x4a1>
   a539a:	mov    %r10d,0x3fca13(%rip)        # 4a1db4 <current_funccal@@Base+0x4ac>
   a53a1:	test   %sil,%sil
   a53a4:	je     a53b3 <do_sub@@Base+0x4b3>
   a53a6:	mov    %edx,0x3fca14(%rip)        # 4a1dc0 <current_funccal@@Base+0x4b8>
   a53ac:	mov    %edx,0xa8(%rsp)
   a53b3:	test   %r14b,%r14b
   a53b6:	je     a53bf <do_sub@@Base+0x4bf>
   a53b8:	mov    %r9d,0x3e88a9(%rip)        # 48dc68 <__data_start@@Base+0x4c68>
   a53bf:	test   %r13b,%r13b
   a53c2:	je     a53ca <do_sub@@Base+0x4ca>
   a53c4:	mov    %ebx,0x3fc9ee(%rip)        # 4a1db8 <current_funccal@@Base+0x4b0>
   a53ca:	test   %r15b,%r15b
   a53cd:	je     a51cf <do_sub@@Base+0x2cf>
   a53d3:	mov    (%rsp),%eax
   a53d6:	mov    %eax,0x3fc9d0(%rip)        # 4a1dac <current_funccal@@Base+0x4a4>
   a53dc:	jmpq   a51cf <do_sub@@Base+0x2cf>
   a53e1:	nopl   0x0(%rax)
   a53e8:	mov    $0x1,%r13d
   a53ee:	mov    $0x1,%ebx
   a53f3:	movb   $0x1,0xc(%rsp)
   a53f8:	movl   $0x1,0x8(%rsp)
   a5400:	jmpq   a5138 <do_sub@@Base+0x238>
   a5405:	mov    $0x1,%r13d
   a540b:	mov    $0x1,%ebx
   a5410:	movb   $0x1,0x18(%rsp)
   a5415:	movl   $0x1,0x10(%rsp)
   a541d:	jmpq   a5138 <do_sub@@Base+0x238>
   a5422:	mov    $0x1,%r15d
   a5428:	movl   $0x69,(%rsp)
   a542f:	jmpq   a5138 <do_sub@@Base+0x238>
   a5434:	movzbl (%rdi),%eax
   a5437:	test   %al,%al
   a5439:	je     a5570 <do_sub@@Base+0x670>
   a543f:	cmp    $0x20,%al
   a5441:	je     a4fb7 <do_sub@@Base+0xb7>
   a5447:	cmp    $0x9,%al
   a5449:	je     a4fb7 <do_sub@@Base+0xb7>
   a544f:	lea    0x175f9c(%rip),%rdi        # 21b3f2 <_IO_stdin_used@@Base+0x4e32>
   a5456:	movzbl %al,%esi
   a5459:	callq  11c810 <vim_strchr@@Base>
   a545e:	test   %rax,%rax
   a5461:	jne    a4fb7 <do_sub@@Base+0xb7>
   a5467:	callq  4f248 <_init@@Base+0x658>
   a546c:	mov    0xc8(%rsp),%rdi
   a5474:	mov    (%rax),%rax
   a5477:	movzbl (%rdi),%ecx
   a547a:	testb  $0x4,0x1(%rax,%rcx,2)
   a547f:	jne    a6bfb <do_sub@@Base+0x1cfb>
   a5485:	cmp    $0x5c,%cl
   a5488:	je     a6ba6 <do_sub@@Base+0x1ca6>
   a548e:	mov    0x4093fc(%rip),%eax        # 4ae890 <p_altkeymap@@Base>
   a5494:	test   %eax,%eax
   a5496:	je     a54b8 <do_sub@@Base+0x5b8>
   a5498:	mov    0x409271(%rip),%rax        # 4ae710 <curwin@@Base>
   a549f:	mov    0x23c(%rax),%r15d
   a54a6:	test   %r15d,%r15d
   a54a9:	je     a54b8 <do_sub@@Base+0x5b8>
   a54ab:	callq  d3870 <lrF_sub@@Base>
   a54b0:	mov    0xc8(%rsp),%rdi
   a54b8:	lea    0x1(%rdi),%r12
   a54bc:	mov    0x40a0de(%rip),%edx        # 4af5a0 <p_magic@@Base>
   a54c2:	mov    0x90(%rsp),%rcx
   a54ca:	mov    %r12,0xc8(%rsp)
   a54d2:	movzbl (%rdi),%r13d
   a54d6:	mov    %r12,%rdi
   a54d9:	mov    %r13d,%esi
   a54dc:	callq  17f3d0 <skip_regexp@@Base>
   a54e1:	mov    %rax,0xc8(%rsp)
   a54e9:	movzbl (%rax),%edx
   a54ec:	mov    %rax,0x20(%rsp)
   a54f1:	cmp    %edx,%r13d
   a54f4:	mov    %edx,%eax
   a54f6:	je     a6b17 <do_sub@@Base+0x1c17>
   a54fc:	test   %dl,%dl
   a54fe:	mov    0x20(%rsp),%rbx
   a5503:	mov    $0x2,%ebp
   a5508:	mov    0x20(%rsp),%rdi
   a550d:	jne    a5557 <do_sub@@Base+0x657>
   a550f:	jmpq   a6ae2 <do_sub@@Base+0x1be2>
   a5514:	nopl   0x0(%rax)
   a5518:	mov    0xc8(%rsp),%rdi
   a5520:	mov    0x4087bd(%rip),%r14d        # 4adce4 <has_mbyte@@Base>
   a5527:	mov    $0x1,%eax
   a552c:	test   %r14d,%r14d
   a552f:	jne    a68c5 <do_sub@@Base+0x19c5>
   a5535:	add    %rax,%rdi
   a5538:	mov    %rdi,0xc8(%rsp)
   a5540:	movzbl (%rdi),%eax
   a5543:	test   %al,%al
   a5545:	je     a68da <do_sub@@Base+0x19da>
   a554b:	movzbl %al,%edx
   a554e:	cmp    %r13d,%edx
   a5551:	je     a6b5c <do_sub@@Base+0x1c5c>
   a5557:	cmp    $0x5c,%al
   a5559:	jne    a5518 <do_sub@@Base+0x618>
   a555b:	cmpb   $0x0,0x1(%rdi)
   a555f:	je     a5518 <do_sub@@Base+0x618>
   a5561:	add    $0x1,%rdi
   a5565:	mov    %rdi,0xc8(%rsp)
   a556d:	jmp    a5520 <do_sub@@Base+0x620>
   a556f:	nop
   a5570:	mov    0x90(%rsp),%rdx
   a5578:	mov    0x30(%rdx),%ecx
   a557b:	test   %ecx,%ecx
   a557d:	je     a4fcc <do_sub@@Base+0xcc>
   a5583:	movl   $0x0,0x98(%rsp)
   a558e:	movq   $0x0,0x20(%rsp)
   a5597:	xor    %r12d,%r12d
   a559a:	jmpq   a5012 <do_sub@@Base+0x112>
   a559f:	lea    0x3fb0fa(%rip),%rsi        # 4a06a0 <e_nopresub@@Base>
   a55a6:	xor    %edi,%edi
   a55a8:	mov    $0x5,%edx
   a55ad:	callq  4ed78 <_init@@Base+0x188>
   a55b2:	mov    %rax,%rdi
   a55b5:	callq  10d330 <emsg@@Base>
   a55ba:	mov    0x228(%rsp),%rax
   a55c2:	xor    %fs:0x28,%rax
   a55cb:	jne    a6b94 <do_sub@@Base+0x1c94>
   a55d1:	add    $0x238,%rsp
   a55d8:	pop    %rbx
   a55d9:	pop    %rbp
   a55da:	pop    %r12
   a55dc:	pop    %r13
   a55de:	pop    %r14
   a55e0:	pop    %r15
   a55e2:	retq   
   a55e3:	movl   $0x0,0x3fc7cf(%rip)        # 4a1dbc <current_funccal@@Base+0x4b4>
   a55ed:	movl   $0x0,0xbc(%rsp)
   a55f8:	jmpq   a51ea <do_sub@@Base+0x2ea>
   a55fd:	mov    %rax,%rdi
   a5600:	callq  b79c0 <check_nextcmd@@Base>
   a5605:	mov    0x90(%rsp),%rdx
   a560d:	test   %rax,%rax
   a5610:	mov    %rax,0x8(%rdx)
   a5614:	jne    a5274 <do_sub@@Base+0x374>
   a561a:	lea    0x3faa7f(%rip),%rsi        # 4a00a0 <e_trailing@@Base>
   a5621:	xor    %edi,%edi
   a5623:	mov    $0x5,%edx
   a5628:	callq  4ed78 <_init@@Base+0x188>
   a562d:	mov    %rax,%rdi
   a5630:	callq  10d330 <emsg@@Base>
   a5635:	jmp    a55ba <do_sub@@Base+0x6ba>
   a5637:	nopw   0x0(%rax,%rax,1)
   a5640:	mov    0x3fc766(%rip),%eax        # 4a1dac <current_funccal@@Base+0x4a4>
   a5646:	cmp    $0x69,%eax
   a5649:	je     a6825 <do_sub@@Base+0x1925>
   a564f:	cmp    $0x49,%eax
   a5652:	je     a6835 <do_sub@@Base+0x1935>
   a5658:	mov    0x20(%rsp),%rax
   a565d:	cmpb   $0x5c,(%rax)
   a5660:	jne    a5668 <do_sub@@Base+0x768>
   a5662:	cmpb   $0x3d,0x1(%rax)
   a5666:	je     a567d <do_sub@@Base+0x77d>
   a5668:	mov    0x409f32(%rip),%esi        # 4af5a0 <p_magic@@Base>
   a566e:	mov    0x20(%rsp),%rdi
   a5673:	callq  17f580 <regtilde@@Base>
   a5678:	mov    %rax,0x20(%rsp)
   a567d:	mov    0x90(%rsp),%rax
   a5685:	mov    0x48(%rax),%rdx
   a5689:	mov    0x40(%rax),%r15
   a568d:	cmp    %r15,%rdx
   a5690:	mov    %rdx,0x38(%rsp)
   a5695:	jl     a6b99 <do_sub@@Base+0x1c99>
   a569b:	lea    0xc0(%rsp),%rax
   a56a3:	movl   $0x0,0x6c(%rsp)
   a56ab:	movq   $0x0,0x60(%rsp)
   a56b4:	movq   $0x0,0x40(%rsp)
   a56bd:	mov    %rax,0x78(%rsp)
   a56c2:	lea    0xc4(%rsp),%rax
   a56ca:	mov    %rax,0x80(%rsp)
   a56d2:	nopw   0x0(%rax,%rax,1)
   a56d8:	callq  c3640 <aborting@@Base>
   a56dd:	test   %eax,%eax
   a56df:	jne    a64b6 <do_sub@@Base+0x15b6>
   a56e5:	mov    0x40868c(%rip),%rdx        # 4add78 <curbuf@@Base>
   a56ec:	mov    0x40901d(%rip),%rsi        # 4ae710 <curwin@@Base>
   a56f3:	xor    %r9d,%r9d
   a56f6:	mov    0x30(%rsp),%rdi
   a56fb:	xor    %r8d,%r8d
   a56fe:	mov    %r15,%rcx
   a5701:	callq  17ff20 <vim_regexec_multi@@Base>
   a5706:	test   %rax,%rax
   a5709:	mov    %rax,%r13
   a570c:	je     a6668 <do_sub@@Base+0x1768>
   a5712:	test   %ebx,%ebx
   a5714:	je     a669f <do_sub@@Base+0x179f>
   a571a:	mov    0xd8(%rsp),%rax
   a5722:	xor    %r14d,%r14d
   a5725:	mov    %r15,0x10(%rsp)
   a572a:	movl   $0x0,0x2c(%rsp)
   a5732:	movl   $0x0,0x48(%rsp)
   a573a:	movl   $0x0,0x8(%rsp)
   a5742:	movl   $0x0,0x28(%rsp)
   a574a:	test   %rax,%rax
   a574d:	movl   $0x0,0x68(%rsp)
   a5755:	movq   $0x0,0x18(%rsp)
   a575e:	movl   $0x0,0x70(%rsp)
   a5766:	movl   $0x7fffffff,0xc(%rsp)
   a576e:	movq   $0x0,(%rsp)
   a5776:	jle    a5a6a <do_sub@@Base+0xb6a>
   a577c:	nopl   0x0(%rax)
   a5780:	mov    (%rsp),%rdi
   a5784:	add    %rax,%r15
   a5787:	add    %rax,0x10(%rsp)
   a578c:	sub    %rax,%r13
   a578f:	callq  11c7f0 <vim_free@@Base>
   a5794:	mov    0x10(%rsp),%rdi
   a5799:	callq  1007a0 <ml_get@@Base>
   a579e:	mov    %rax,%rdi
   a57a1:	callq  11f220 <vim_strsave@@Base>
   a57a6:	test   %rax,%rax
   a57a9:	mov    %rax,(%rsp)
   a57ad:	je     a6741 <do_sub@@Base+0x1841>
   a57b3:	nopl   0x0(%rax,%rax,1)
   a57b8:	mov    0xc(%rsp),%ecx
   a57bc:	cmp    %ecx,0x8(%rsp)
   a57c0:	mov    0x408f49(%rip),%rbp        # 4ae710 <curwin@@Base>
   a57c7:	mov    0x180(%rsp),%eax
   a57ce:	mov    %r15,0x38(%rbp)
   a57d2:	je     a5ba0 <do_sub@@Base+0xca0>
   a57d8:	mov    %eax,0xc(%rsp)
   a57dc:	mov    0x3fc5d1(%rip),%r12d        # 4a1db4 <current_funccal@@Base+0x4ac>
   a57e3:	mov    0xc(%rsp),%eax
   a57e7:	test   %r12d,%r12d
   a57ea:	mov    %eax,0x8(%rsp)
   a57ee:	je     a5af8 <do_sub@@Base+0xbf8>
   a57f4:	cmp    $0x1,%r13
   a57f8:	jle    a5815 <do_sub@@Base+0x915>
   a57fa:	mov    (%rsp),%rdi
   a57fe:	mov    $0x1,%r13d
   a5804:	callq  4ed80 <_init@@Base+0x190>
   a5809:	movl   $0x1,0x2c(%rsp)
   a5811:	mov    %eax,0x8(%rsp)
   a5815:	mov    0x20(%rsp),%rax
   a581a:	addq   $0x1,0x409d9e(%rip)        # 4af5c0 <sub_nsubs@@Base>
   a5822:	xor    %ebx,%ebx
   a5824:	movl   $0x1,0x48(%rsp)
   a582c:	cmpb   $0x5c,(%rax)
   a582f:	je     a5ae8 <do_sub@@Base+0xbe8>
   a5835:	mov    0x2c(%rsp),%eax
   a5839:	test   %eax,%eax
   a583b:	jne    a5ad0 <do_sub@@Base+0xbd0>
   a5841:	mov    0x4083b9(%rip),%eax        # 4adc00 <got_int@@Base>
   a5847:	test   %eax,%eax
   a5849:	jne    a5ad0 <do_sub@@Base+0xbd0>
   a584f:	mov    0x68(%rsp),%eax
   a5853:	test   %eax,%eax
   a5855:	jne    a5ad0 <do_sub@@Base+0xbd0>
   a585b:	cmp    0x38(%rsp),%r15
   a5860:	jg     a5ad0 <do_sub@@Base+0xbd0>
   a5866:	or     0x3fc554(%rip),%ebx        # 4a1dc0 <current_funccal@@Base+0x4b8>
   a586c:	je     a5ad0 <do_sub@@Base+0xbd0>
   a5872:	movslq 0x8(%rsp),%rax
   a5877:	mov    (%rsp),%rcx
   a587b:	cmpb   $0x0,(%rcx,%rax,1)
   a587f:	jne    a588b <do_sub@@Base+0x98b>
   a5881:	cmp    $0x1,%r13
   a5885:	jle    a66e6 <do_sub@@Base+0x17e6>
   a588b:	cmpq   $0x0,0x18(%rsp)
   a5891:	jg     a6c4a <do_sub@@Base+0x1d4a>
   a5897:	mov    0x8(%rsp),%r8d
   a589c:	mov    0x10(%rsp),%rcx
   a58a1:	xor    %r9d,%r9d
   a58a4:	mov    0x4084cd(%rip),%rdx        # 4add78 <curbuf@@Base>
   a58ab:	mov    0x408e5e(%rip),%rsi        # 4ae710 <curwin@@Base>
   a58b2:	mov    0x30(%rsp),%rdi
   a58b7:	callq  17ff20 <vim_regexec_multi@@Base>
   a58bc:	test   %rax,%rax
   a58bf:	mov    %rax,%r13
   a58c2:	je     a58d3 <do_sub@@Base+0x9d3>
   a58c4:	cmpq   $0x0,0xd8(%rsp)
   a58cd:	jle    a5a54 <do_sub@@Base+0xb54>
   a58d3:	xor    %r12d,%r12d
   a58d6:	test   %r14,%r14
   a58d9:	je     a5a15 <do_sub@@Base+0xb15>
   a58df:	movslq 0x28(%rsp),%rsi
   a58e4:	mov    (%rsp),%rbx
   a58e8:	mov    %r14,%rdi
   a58eb:	add    %rbx,%rsi
   a58ee:	callq  4f180 <_init@@Base+0x590>
   a58f3:	mov    %rbx,%rdi
   a58f6:	callq  4ed80 <_init@@Base+0x190>
   a58fb:	mov    %eax,%ecx
   a58fd:	sub    0xc(%rsp),%eax
   a5901:	sub    0x8(%rsp),%ecx
   a5905:	mov    %r15,%rdi
   a5908:	mov    %ecx,0x8(%rsp)
   a590c:	mov    %eax,0xc(%rsp)
   a5910:	callq  1d4fa0 <u_savesub@@Base>
   a5915:	cmp    $0x1,%eax
   a5918:	jne    a6697 <do_sub@@Base+0x1797>
   a591e:	mov    $0x1,%edx
   a5923:	mov    %r14,%rsi
   a5926:	mov    %r15,%rdi
   a5929:	callq  ff8d0 <ml_replace@@Base>
   a592e:	cmpq   $0x0,0x18(%rsp)
   a5934:	mov    0x3fc482(%rip),%eax        # 4a1dbc <current_funccal@@Base+0x4b4>
   a593a:	jle    a5eb4 <do_sub@@Base+0xfb4>
   a5940:	lea    0x1(%r15),%rbx
   a5944:	mov    0x18(%rsp),%rsi
   a5949:	mov    %rbx,%rdi
   a594c:	callq  1d5000 <u_savedel@@Base>
   a5951:	cmp    $0x1,%eax
   a5954:	jne    a66bd <do_sub@@Base+0x17bd>
   a595a:	xor    %ebp,%ebp
   a595c:	mov    %r12d,0x10(%rsp)
   a5961:	mov    %rbp,%r12
   a5964:	mov    %rbx,%rbp
   a5967:	mov    0x18(%rsp),%rbx
   a596c:	jmp    a5973 <do_sub@@Base+0xa73>
   a596e:	xchg   %ax,%ax
   a5970:	mov    %rax,%r12
   a5973:	xor    %esi,%esi
   a5975:	mov    %rbp,%rdi
   a5978:	callq  100950 <ml_delete@@Base>
   a597d:	lea    0x1(%r12),%rax
   a5982:	cmp    %rax,%rbx
   a5985:	jne    a5970 <do_sub@@Base+0xa70>
   a5987:	mov    %rbp,%rbx
   a598a:	mov    %r12,%rbp
   a598d:	mov    $0x7fffffff,%edx
   a5992:	mov    %rbp,%rcx
   a5995:	mov    0x18(%rsp),%rbp
   a599a:	mov    %rbx,%rdi
   a599d:	not    %rcx
   a59a0:	mov    0x10(%rsp),%r12d
   a59a5:	lea    -0x1(%rbp,%rbx,1),%rsi
   a59aa:	callq  fa660 <mark_adjust@@Base>
   a59af:	mov    0x3fc407(%rip),%eax        # 4a1dbc <current_funccal@@Base+0x4b4>
   a59b5:	test   %eax,%eax
   a59b7:	jne    a5e90 <do_sub@@Base+0xf90>
   a59bd:	sub    %rbp,0x38(%rsp)
   a59c2:	movq   $0x0,0x18(%rsp)
   a59cb:	mov    0x40(%rsp),%rax
   a59d0:	mov    %rbx,0x60(%rsp)
   a59d5:	test   %rax,%rax
   a59d8:	cmove  %r15,%rax
   a59dc:	mov    %rax,0x40(%rsp)
   a59e1:	mov    (%rsp),%rdi
   a59e5:	callq  11c7f0 <vim_free@@Base>
   a59ea:	mov    %r14,%rdi
   a59ed:	callq  4ed80 <_init@@Base+0x190>
   a59f2:	mov    %eax,%ecx
   a59f4:	sub    0xc(%rsp),%eax
   a59f8:	sub    0x8(%rsp),%ecx
   a59fc:	mov    %r15,0x10(%rsp)
   a5a01:	movl   $0x0,0x28(%rsp)
   a5a09:	mov    %r14,(%rsp)
   a5a0d:	mov    %ecx,0x8(%rsp)
   a5a11:	mov    %eax,0xc(%rsp)
   a5a15:	cmp    $0xffffffffffffffff,%r13
   a5a19:	jne    a5a48 <do_sub@@Base+0xb48>
   a5a1b:	test   %r12d,%r12d
   a5a1e:	jne    a5a48 <do_sub@@Base+0xb48>
   a5a20:	mov    0x8(%rsp),%r8d
   a5a25:	mov    0x10(%rsp),%rcx
   a5a2a:	xor    %r9d,%r9d
   a5a2d:	mov    0x408344(%rip),%rdx        # 4add78 <curbuf@@Base>
   a5a34:	mov    0x408cd5(%rip),%rsi        # 4ae710 <curwin@@Base>
   a5a3b:	mov    0x30(%rsp),%rdi
   a5a40:	callq  17ff20 <vim_regexec_multi@@Base>
   a5a45:	mov    %rax,%r13
   a5a48:	test   %r13,%r13
   a5a4b:	jle    a6460 <do_sub@@Base+0x1560>
   a5a51:	xor    %r14d,%r14d
   a5a54:	callq  119f10 <line_breakcheck@@Base>
   a5a59:	mov    0xd8(%rsp),%rax
   a5a61:	test   %rax,%rax
   a5a64:	jg     a5780 <do_sub@@Base+0x880>
   a5a6a:	cmpq   $0x0,(%rsp)
   a5a6f:	jne    a57b8 <do_sub@@Base+0x8b8>
   a5a75:	jmpq   a5794 <do_sub@@Base+0x894>
   a5a7a:	mov    0x74(%rsp),%eax
   a5a7e:	mov    0x88(%rsp),%r13
   a5a86:	mov    %eax,0x3fb2e0(%rip)        # 4a0d6c <State@@Base>
   a5a8c:	callq  1cd450 <setmouse@@Base>
   a5a91:	mov    0x40a0d0(%rip),%rdi        # 4afb68 <p_cpo@@Base>
   a5a98:	mov    $0x75,%esi
   a5a9d:	callq  11c810 <vim_strchr@@Base>
   a5aa2:	test   %rax,%rax
   a5aa5:	je     a5aae <do_sub@@Base+0xbae>
   a5aa7:	subl   $0x1,0x40820e(%rip)        # 4adcbc <no_u_sync@@Base>
   a5aae:	cmp    $0x1,%r13
   a5ab2:	jle    a63f8 <do_sub@@Base+0x14f8>
   a5ab8:	mov    (%rsp),%rdi
   a5abc:	callq  4ed80 <_init@@Base+0x190>
   a5ac1:	movl   $0x1,0x2c(%rsp)
   a5ac9:	mov    %eax,0x8(%rsp)
   a5acd:	nopl   (%rax)
   a5ad0:	mov    $0x1,%r12d
   a5ad6:	mov    $0xffffffffffffffff,%r13
   a5add:	jmpq   a58d6 <do_sub@@Base+0x9d6>
   a5ae2:	nopw   0x0(%rax,%rax,1)
   a5ae8:	cmpb   $0x3d,0x1(%rax)
   a5aec:	jne    a5835 <do_sub@@Base+0x935>
   a5af2:	nopw   0x0(%rax,%rax,1)
   a5af8:	mov    0x3fc2be(%rip),%eax        # 4a1dbc <current_funccal@@Base+0x4b4>
   a5afe:	test   %eax,%eax
   a5b00:	jne    a5ed0 <do_sub@@Base+0xfd0>
   a5b06:	mov    0xe0(%rsp),%eax
   a5b0d:	test   %r12d,%r12d
   a5b10:	mov    %eax,0x40(%rbp)
   a5b13:	je     a5b37 <do_sub@@Base+0xc37>
   a5b15:	mov    0x40825c(%rip),%rax        # 4add78 <curbuf@@Base>
   a5b1c:	addl   $0x1,0x408219(%rip)        # 4add3c <sandbox@@Base>
   a5b23:	mov    0x14e0(%rax),%edx
   a5b29:	movl   $0x0,0x14e0(%rax)
   a5b33:	mov    %edx,0x6c(%rsp)
   a5b37:	mov    0x10(%rsp),%rsi
   a5b3c:	sub    $0x8,%rsp
   a5b40:	sub    0xe0(%rsp),%rsi
   a5b48:	mov    0x409a51(%rip),%r9d        # 4af5a0 <p_magic@@Base>
   a5b4f:	pushq  $0x1
   a5b51:	xor    %r8d,%r8d
   a5b54:	mov    0x10(%rsp),%rcx
   a5b59:	mov    0x30(%rsp),%rdx
   a5b5e:	mov    0x40(%rsp),%rdi
   a5b63:	callq  17f7c0 <vim_regsub_multi@@Base>
   a5b68:	mov    0x3fc245(%rip),%r8d        # 4a1db4 <current_funccal@@Base+0x4ac>
   a5b6f:	mov    %eax,%r12d
   a5b72:	mov    0x4081ff(%rip),%rax        # 4add78 <curbuf@@Base>
   a5b79:	pop    %rsi
   a5b7a:	pop    %rdi
   a5b7b:	test   %r8d,%r8d
   a5b7e:	je     a5bf0 <do_sub@@Base+0xcf0>
   a5b80:	mov    0x6c(%rsp),%ecx
   a5b84:	subl   $0x1,0x4081b1(%rip)        # 4add3c <sandbox@@Base>
   a5b8b:	xor    %ebx,%ebx
   a5b8d:	mov    %ecx,0x14e0(%rax)
   a5b93:	jmpq   a5835 <do_sub@@Base+0x935>
   a5b98:	nopl   0x0(%rax,%rax,1)
   a5ba0:	cmpq   $0x0,0x178(%rsp)
   a5ba9:	jne    a57d8 <do_sub@@Base+0x8d8>
   a5baf:	cmp    %eax,0x8(%rsp)
   a5bb3:	mov    %eax,0xc(%rsp)
   a5bb7:	jne    a57dc <do_sub@@Base+0x8dc>
   a5bbd:	movslq 0x8(%rsp),%rdi
   a5bc2:	add    (%rsp),%rdi
   a5bc6:	cmpb   $0x0,(%rdi)
   a5bc9:	je     a6446 <do_sub@@Base+0x1546>
   a5bcf:	mov    0x40810f(%rip),%ebx        # 4adce4 <has_mbyte@@Base>
   a5bd5:	test   %ebx,%ebx
   a5bd7:	jne    a66c8 <do_sub@@Base+0x17c8>
   a5bdd:	addl   $0x1,0x8(%rsp)
   a5be2:	jmpq   a5835 <do_sub@@Base+0x935>
   a5be7:	nopw   0x0(%rax,%rax,1)
   a5bf0:	mov    (%rax),%rax
   a5bf3:	sub    0x10(%rsp),%rax
   a5bf8:	add    $0x1,%rax
   a5bfc:	cmp    %rax,%r13
   a5bff:	jle    a5c0c <do_sub@@Base+0xd0c>
   a5c01:	mov    %rax,%r13
   a5c04:	movl   $0x1,0x2c(%rsp)
   a5c0c:	cmp    $0x1,%r13
   a5c10:	mov    (%rsp),%rdi
   a5c14:	je     a5c37 <do_sub@@Base+0xd37>
   a5c16:	mov    0x10(%rsp),%rax
   a5c1b:	lea    -0x1(%r13,%rax,1),%rdi
   a5c20:	callq  1007a0 <ml_get@@Base>
   a5c25:	mov    %rax,%rdi
   a5c28:	mov    0x18(%rsp),%rax
   a5c2d:	lea    -0x1(%r13,%rax,1),%rax
   a5c32:	mov    %rax,0x18(%rsp)
   a5c37:	mov    0xe0(%rsp),%ebx
   a5c3e:	sub    0x28(%rsp),%ebx
   a5c42:	callq  4ed80 <_init@@Base+0x190>
   a5c47:	mov    %ebx,%edx
   a5c49:	sub    0x180(%rsp),%edx
   a5c50:	lea    0x1(%r12,%rdx,1),%ebp
   a5c55:	add    %eax,%ebp
   a5c57:	test   %r14,%r14
   a5c5a:	je     a6672 <do_sub@@Base+0x1772>
   a5c60:	mov    %r14,%rdi
   a5c63:	callq  4ed80 <_init@@Base+0x190>
   a5c68:	add    %eax,%ebp
   a5c6a:	cmp    0x70(%rsp),%ebp
   a5c6e:	mov    %rax,%r12
   a5c71:	jg     a6350 <do_sub@@Base+0x1450>
   a5c77:	movslq %r12d,%r10
   a5c7a:	add    %r14,%r10
   a5c7d:	movslq 0x28(%rsp),%rsi
   a5c82:	movslq %ebx,%rbx
   a5c85:	mov    %r10,%rdi
   a5c88:	add    (%rsp),%rsi
   a5c8c:	mov    %rbx,%rdx
   a5c8f:	callq  4f0d0 <_init@@Base+0x4e0>
   a5c94:	mov    0x10(%rsp),%rbp
   a5c99:	sub    $0x8,%rsp
   a5c9d:	lea    (%rax,%rbx,1),%r12
   a5ca1:	mov    0x4098f8(%rip),%r9d        # 4af5a0 <p_magic@@Base>
   a5ca8:	mov    $0x1,%r8d
   a5cae:	xor    %ebx,%ebx
   a5cb0:	mov    %r12,%rcx
   a5cb3:	mov    %rbp,%rsi
   a5cb6:	sub    0xe0(%rsp),%rsi
   a5cbe:	pushq  $0x1
   a5cc0:	mov    0x30(%rsp),%rdx
   a5cc5:	mov    0x40(%rsp),%rdi
   a5cca:	callq  17f7c0 <vim_regsub_multi@@Base>
   a5ccf:	mov    0x408a3a(%rip),%rax        # 4ae710 <curwin@@Base>
   a5cd6:	addq   $0x1,0x4098e2(%rip)        # 4af5c0 <sub_nsubs@@Base>
   a5cde:	cmp    $0x1,%r13
   a5ce2:	movl   $0x0,0x40(%rax)
   a5ce9:	pop    %rdx
   a5cea:	pop    %rcx
   a5ceb:	jle    a5d2f <do_sub@@Base+0xe2f>
   a5ced:	lea    -0x1(%r13,%rbp,1),%rdx
   a5cf2:	mov    (%rsp),%rdi
   a5cf6:	mov    $0x1,%ebx
   a5cfb:	mov    %rdx,%rbp
   a5cfe:	mov    %rdx,0x10(%rsp)
   a5d03:	callq  11c7f0 <vim_free@@Base>
   a5d08:	mov    %rbp,%rdi
   a5d0b:	callq  1007a0 <ml_get@@Base>
   a5d10:	mov    %rax,%rdi
   a5d13:	callq  11f220 <vim_strsave@@Base>
   a5d18:	cmp    %rbp,0x38(%rsp)
   a5d1d:	mov    %rax,(%rsp)
   a5d21:	jge    a5d2f <do_sub@@Base+0xe2f>
   a5d23:	movl   $0x0,0x3fc093(%rip)        # 4a1dc0 <current_funccal@@Base+0x4b8>
   a5d2d:	xor    %ebx,%ebx
   a5d2f:	mov    0x2c(%rsp),%eax
   a5d33:	test   %eax,%eax
   a5d35:	jne    a6320 <do_sub@@Base+0x1420>
   a5d3b:	mov    0x180(%rsp),%eax
   a5d42:	mov    %eax,0x28(%rsp)
   a5d46:	movzbl (%r12),%eax
   a5d4b:	test   %al,%al
   a5d4d:	je     a5db8 <do_sub@@Base+0xeb8>
   a5d4f:	lea    -0x1(%r14),%rcx
   a5d53:	mov    %rcx,0x48(%rsp)
   a5d58:	jmp    a5d7d <do_sub@@Base+0xe7d>
   a5d5a:	nopw   0x0(%rax,%rax,1)
   a5d60:	cmp    $0xd,%al
   a5d62:	je     a5de0 <do_sub@@Base+0xee0>
   a5d64:	mov    0x407f7a(%rip),%eax        # 4adce4 <has_mbyte@@Base>
   a5d6a:	test   %eax,%eax
   a5d6c:	jne    a5dc8 <do_sub@@Base+0xec8>
   a5d6e:	mov    %r12,%rax
   a5d71:	add    $0x1,%r12
   a5d75:	movzbl 0x1(%rax),%eax
   a5d79:	test   %al,%al
   a5d7b:	je     a5db8 <do_sub@@Base+0xeb8>
   a5d7d:	cmp    $0x5c,%al
   a5d7f:	jne    a5d60 <do_sub@@Base+0xe60>
   a5d81:	cmpb   $0x0,0x1(%r12)
   a5d87:	je     a5d64 <do_sub@@Base+0xe64>
   a5d89:	lea    0x1(%r12),%rbp
   a5d8e:	mov    %rbp,%rdi
   a5d91:	callq  4ed80 <_init@@Base+0x190>
   a5d96:	lea    0x1(%rax),%rdx
   a5d9a:	mov    %r12,%rdi
   a5d9d:	mov    %rbp,%rsi
   a5da0:	callq  4f0d0 <_init@@Base+0x4e0>
   a5da5:	mov    %r12,%rax
   a5da8:	mov    %rbp,%r12
   a5dab:	movzbl 0x1(%rax),%eax
   a5daf:	test   %al,%al
   a5db1:	jne    a5d7d <do_sub@@Base+0xe7d>
   a5db3:	nopl   0x0(%rax,%rax,1)
   a5db8:	movl   $0x1,0x48(%rsp)
   a5dc0:	jmpq   a5835 <do_sub@@Base+0x935>
   a5dc5:	nopl   (%rax)
   a5dc8:	mov    %r12,%rdi
   a5dcb:	callq  *0x3fb277(%rip)        # 4a1048 <mb_ptr2len@@Base>
   a5dd1:	sub    $0x1,%eax
   a5dd4:	cltq   
   a5dd6:	add    %r12,%rax
   a5dd9:	lea    0x1(%rax),%r12
   a5ddd:	jmp    a5d75 <do_sub@@Base+0xe75>
   a5ddf:	nop
   a5de0:	mov    %r15,%rdi
   a5de3:	callq  1d4fd0 <u_inssub@@Base>
   a5de8:	cmp    $0x1,%eax
   a5deb:	jne    a5d6e <do_sub@@Base+0xe6e>
   a5df1:	lea    -0x1(%r15),%rax
   a5df5:	mov    %r12,%rdx
   a5df8:	lea    0x1(%r15),%rbp
   a5dfc:	sub    %r14,%rdx
   a5dff:	xor    %ecx,%ecx
   a5e01:	mov    %r14,%rsi
   a5e04:	add    $0x1,%edx
   a5e07:	mov    %rax,%rdi
   a5e0a:	movb   $0x0,(%r12)
   a5e0f:	mov    %rax,0x50(%rsp)
   a5e14:	callq  100830 <ml_append@@Base>
   a5e19:	xor    %ecx,%ecx
   a5e1b:	mov    $0x1,%edx
   a5e20:	mov    $0x7fffffff,%esi
   a5e25:	mov    %rbp,%rdi
   a5e28:	callq  fa660 <mark_adjust@@Base>
   a5e2d:	mov    0x3fbf89(%rip),%eax        # 4a1dbc <current_funccal@@Base+0x4b4>
   a5e33:	test   %eax,%eax
   a5e35:	jne    a66a9 <do_sub@@Base+0x17a9>
   a5e3b:	cmpq   $0x0,0x40(%rsp)
   a5e41:	mov    %rbp,0x60(%rsp)
   a5e46:	jne    a5e4d <do_sub@@Base+0xf4d>
   a5e48:	mov    %r15,0x40(%rsp)
   a5e4d:	mov    0x4088bc(%rip),%rax        # 4ae710 <curwin@@Base>
   a5e54:	add    $0x1,%r12
   a5e58:	addq   $0x1,0x10(%rsp)
   a5e5e:	mov    %r12,%rdi
   a5e61:	addq   $0x1,0x38(%rsp)
   a5e67:	mov    %rbp,%r15
   a5e6a:	addq   $0x1,0x38(%rax)
   a5e6f:	callq  4ed80 <_init@@Base+0x190>
   a5e74:	lea    0x1(%rax),%rdx
   a5e78:	mov    %r12,%rsi
   a5e7b:	mov    %r14,%rdi
   a5e7e:	mov    %r14,%r12
   a5e81:	callq  4f0d0 <_init@@Base+0x4e0>
   a5e86:	mov    0x48(%rsp),%rax
   a5e8b:	jmpq   a5d75 <do_sub@@Base+0xe75>
   a5e90:	mov    0x18(%rsp),%rbp
   a5e95:	mov    %rbx,%rdi
   a5e98:	mov    %rbp,%rsi
   a5e9b:	callq  111c50 <deleted_lines@@Base>
   a5ea0:	sub    %rbp,0x38(%rsp)
   a5ea5:	mov    0x3fbf11(%rip),%eax        # 4a1dbc <current_funccal@@Base+0x4b4>
   a5eab:	movq   $0x0,0x18(%rsp)
   a5eb4:	test   %eax,%eax
   a5eb6:	lea    0x1(%r15),%rbx
   a5eba:	je     a59cb <do_sub@@Base+0xacb>
   a5ec0:	xor    %esi,%esi
   a5ec2:	mov    %r15,%rdi
   a5ec5:	callq  110a20 <changed_bytes@@Base>
   a5eca:	jmpq   a59e1 <do_sub@@Base+0xae1>
   a5ecf:	nop
   a5ed0:	mov    0x3fae96(%rip),%eax        # 4a0d6c <State@@Base>
   a5ed6:	movl   $0x800,0x3fae8c(%rip)        # 4a0d6c <State@@Base>
   a5ee0:	mov    %eax,0x74(%rsp)
   a5ee4:	callq  1cd450 <setmouse@@Base>
   a5ee9:	mov    0xe0(%rsp),%edx
   a5ef0:	mov    0x408819(%rip),%rax        # 4ae710 <curwin@@Base>
   a5ef7:	mov    $0x75,%esi
   a5efc:	mov    0x409c65(%rip),%rdi        # 4afb68 <p_cpo@@Base>
   a5f03:	mov    %edx,0x40(%rax)
   a5f06:	callq  11c810 <vim_strchr@@Base>
   a5f0b:	test   %rax,%rax
   a5f0e:	je     a5f17 <do_sub@@Base+0x1017>
   a5f10:	addl   $0x1,0x407da5(%rip)        # 4adcbc <no_u_sync@@Base>
   a5f17:	movslq 0x28(%rsp),%rax
   a5f1c:	xor    %r12d,%r12d
   a5f1f:	mov    %r13,0x88(%rsp)
   a5f27:	add    (%rsp),%rax
   a5f2b:	mov    %rax,0x58(%rsp)
   a5f30:	mov    0x3fbe85(%rip),%r10d        # 4a1dbc <current_funccal@@Base+0x4b4>
   a5f37:	test   %r10d,%r10d
   a5f3a:	je     a61b7 <do_sub@@Base+0x12b7>
   a5f40:	mov    0x407d92(%rip),%ebx        # 4adcd8 <exmode_active@@Base>
   a5f46:	test   %ebx,%ebx
   a5f48:	jne    a61e0 <do_sub@@Base+0x12e0>
   a5f4e:	mov    0x4087bb(%rip),%rax        # 4ae710 <curwin@@Base>
   a5f55:	test   %r14,%r14
   a5f58:	mov    0x407d19(%rip),%r12d        # 4adc78 <RedrawingDisabled@@Base>
   a5f5f:	movl   $0x0,0x407d0f(%rip)        # 4adc78 <RedrawingDisabled@@Base>
   a5f69:	mov    0x1bc(%rax),%r13d
   a5f70:	movl   $0x0,0x1bc(%rax)
   a5f7a:	je     a61d0 <do_sub@@Base+0x12d0>
   a5f80:	mov    %r15,%rdi
   a5f83:	callq  1007a0 <ml_get@@Base>
   a5f88:	mov    %rax,%rdi
   a5f8b:	callq  11f220 <vim_strsave@@Base>
   a5f90:	test   %rax,%rax
   a5f93:	mov    %rax,%rbp
   a5f96:	je     a61d0 <do_sub@@Base+0x12d0>
   a5f9c:	mov    0x58(%rsp),%rsi
   a5fa1:	mov    %r14,%rdi
   a5fa4:	callq  113200 <concat_str@@Base>
   a5fa9:	test   %rax,%rax
   a5fac:	je     a61c8 <do_sub@@Base+0x12c8>
   a5fb2:	mov    %rax,%rdi
   a5fb5:	mov    %rax,0x50(%rsp)
   a5fba:	callq  4ed80 <_init@@Base+0x190>
   a5fbf:	mov    %rbp,%rdi
   a5fc2:	mov    %rax,%rbx
   a5fc5:	callq  4ed80 <_init@@Base+0x190>
   a5fca:	sub    %eax,%ebx
   a5fcc:	mov    0x40873d(%rip),%rax        # 4ae710 <curwin@@Base>
   a5fd3:	mov    0x50(%rsp),%rsi
   a5fd8:	xor    %edx,%edx
   a5fda:	mov    %r15,%rdi
   a5fdd:	add    %ebx,0x40(%rax)
   a5fe0:	callq  ff8d0 <ml_replace@@Base>
   a5fe5:	add    0x180(%rsp),%ebx
   a5fec:	mov    0x178(%rsp),%rax
   a5ff4:	sub    0xd8(%rsp),%rax
   a5ffc:	movl   $0x1,0x407e0a(%rip)        # 4ade10 <highlight_match@@Base>
   a6006:	mov    %ebx,0x4086a8(%rip)        # 4ae6b4 <search_match_endcol@@Base>
   a600c:	mov    %rax,0x408d95(%rip)        # 4aeda8 <search_match_lines@@Base>
   a6013:	callq  1239f0 <update_topline@@Base>
   a6018:	callq  1249a0 <validate_cursor@@Base>
   a601d:	mov    $0x23,%edi
   a6022:	callq  190f80 <update_screen@@Base>
   a6027:	mov    $0x23,%edi
   a602c:	movl   $0x0,0x407dda(%rip)        # 4ade10 <highlight_match@@Base>
   a6036:	callq  180f60 <redraw_later@@Base>
   a603b:	mov    0x4086ce(%rip),%rax        # 4ae710 <curwin@@Base>
   a6042:	movslq 0x4083c7(%rip),%rdx        # 4ae410 <msg_row@@Base>
   a6049:	mov    %r13d,0x1bc(%rax)
   a6050:	mov    0x3fad59(%rip),%rax        # 4a0db0 <Rows@@Base>
   a6057:	sub    $0x1,%rax
   a605b:	cmp    %rax,%rdx
   a605e:	je     a62f8 <do_sub@@Base+0x13f8>
   a6064:	callq  1076b0 <msg_starthere@@Base>
   a6069:	lea    0x175b40(%rip),%rsi        # 21bbb0 <_IO_stdin_used@@Base+0x55f0>
   a6070:	xor    %edi,%edi
   a6072:	mov    $0x5,%edx
   a6077:	mov    0x407e63(%rip),%ebx        # 4adee0 <msg_scroll@@Base>
   a607d:	movl   $0x1,0x407df9(%rip)        # 4ade80 <msg_no_more@@Base>
   a6087:	movl   $0x0,0x407e4f(%rip)        # 4adee0 <msg_scroll@@Base>
   a6091:	callq  4ed78 <_init@@Base+0x188>
   a6096:	mov    0x20(%rsp),%rdx
   a609b:	mov    0x40944b(%rip),%edi        # 4af4ec <highlight_attr@@Base+0x2c>
   a60a1:	mov    %rax,%rsi
   a60a4:	xor    %eax,%eax
   a60a6:	callq  10daa0 <smsg_attr@@Base>
   a60ab:	mov    $0x1,%edi
   a60b0:	movl   $0x0,0x407dc6(%rip)        # 4ade80 <msg_no_more@@Base>
   a60ba:	mov    %ebx,0x407e20(%rip)        # 4adee0 <msg_scroll@@Base>
   a60c0:	callq  188bb0 <showruler@@Base>
   a60c5:	mov    0x4092f5(%rip),%esi        # 4af3c0 <msg_col@@Base>
   a60cb:	mov    0x40833f(%rip),%edi        # 4ae410 <msg_row@@Base>
   a60d1:	callq  182610 <windgoto@@Base>
   a60d6:	mov    %r12d,0x407b9b(%rip)        # 4adc78 <RedrawingDisabled@@Base>
   a60dd:	addl   $0x1,0x407be4(%rip)        # 4adcc8 <no_mapping@@Base>
   a60e4:	addl   $0x1,0x407bd5(%rip)        # 4adcc0 <allow_keys@@Base>
   a60eb:	callq  ec680 <plain_vgetc@@Base>
   a60f0:	mov    $0x1,%edi
   a60f5:	subl   $0x1,0x407bc4(%rip)        # 4adcc0 <allow_keys@@Base>
   a60fc:	mov    %eax,%r12d
   a60ff:	subl   $0x1,0x407bc2(%rip)        # 4adcc8 <no_mapping@@Base>
   a6106:	movl   $0x0,0x407dcc(%rip)        # 4adedc <msg_didout@@Base>
   a6110:	movl   $0x0,0x4092a6(%rip)        # 4af3c0 <msg_col@@Base>
   a611a:	callq  c8120 <gotocmdline@@Base>
   a611f:	test   %rbp,%rbp
   a6122:	je     a6131 <do_sub@@Base+0x1231>
   a6124:	xor    %edx,%edx
   a6126:	mov    %rbp,%rsi
   a6129:	mov    %r15,%rdi
   a612c:	callq  ff8d0 <ml_replace@@Base>
   a6131:	cmp    $0x71,%r12d
   a6135:	movl   $0x0,0x407d65(%rip)        # 4adea4 <need_wait_return@@Base>
   a613f:	je     a6390 <do_sub@@Base+0x1490>
   a6145:	cmp    $0x1b,%r12d
   a6149:	je     a6390 <do_sub@@Base+0x1490>
   a614f:	cmp    $0x3,%r12d
   a6153:	je     a63ff <do_sub@@Base+0x14ff>
   a6159:	cmp    0x407d34(%rip),%r12d        # 4ade94 <intr_char@@Base>
   a6160:	je     a6390 <do_sub@@Base+0x1490>
   a6166:	cmp    $0x6e,%r12d
   a616a:	je     a5a7a <do_sub@@Base+0xb7a>
   a6170:	cmp    $0x79,%r12d
   a6174:	je     a6605 <do_sub@@Base+0x1705>
   a617a:	cmp    $0x6c,%r12d
   a617e:	je     a663b <do_sub@@Base+0x173b>
   a6184:	cmp    $0x61,%r12d
   a6188:	je     a6654 <do_sub@@Base+0x1754>
   a618e:	cmp    $0x5,%r12d
   a6192:	je     a6310 <do_sub@@Base+0x1410>
   a6198:	cmp    $0x19,%r12d
   a619c:	jne    a5f30 <do_sub@@Base+0x1030>
   a61a2:	callq  124d30 <scrolldown_clamp@@Base>
   a61a7:	mov    0x3fbc0e(%rip),%r10d        # 4a1dbc <current_funccal@@Base+0x4b4>
   a61ae:	test   %r10d,%r10d
   a61b1:	jne    a5f40 <do_sub@@Base+0x1040>
   a61b7:	mov    0x88(%rsp),%r13
   a61bf:	jmpq   a63a0 <do_sub@@Base+0x14a0>
   a61c4:	nopl   0x0(%rax)
   a61c8:	mov    %rbp,%rdi
   a61cb:	callq  11c7f0 <vim_free@@Base>
   a61d0:	xor    %ebp,%ebp
   a61d2:	jmpq   a5fe5 <do_sub@@Base+0x10e5>
   a61d7:	nopw   0x0(%rax,%rax,1)
   a61e0:	mov    0x3fbbc2(%rip),%edx        # 4a1da8 <current_funccal@@Base+0x4a0>
   a61e6:	mov    0x3fbbc4(%rip),%esi        # 4a1db0 <current_funccal@@Base+0x4a8>
   a61ec:	mov    %r15,%rdi
   a61ef:	callq  a19b0 <print_line_no_prefix@@Base>
   a61f4:	mov    0x408515(%rip),%rdi        # 4ae710 <curwin@@Base>
   a61fb:	mov    0x78(%rsp),%rdx
   a6200:	xor    %r8d,%r8d
   a6203:	xor    %ecx,%ecx
   a6205:	lea    0x38(%rdi),%rsi
   a6209:	callq  60170 <getvcol@@Base>
   a620e:	mov    0x4084fb(%rip),%rdi        # 4ae710 <curwin@@Base>
   a6215:	mov    0x180(%rsp),%eax
   a621c:	xor    %ecx,%ecx
   a621e:	mov    0x80(%rsp),%r8
   a6226:	xor    %edx,%edx
   a6228:	sub    $0x1,%eax
   a622b:	lea    0x38(%rdi),%rsi
   a622f:	mov    %eax,0x40(%rdi)
   a6232:	callq  60170 <getvcol@@Base>
   a6237:	mov    0x3fbb73(%rip),%ebp        # 4a1db0 <current_funccal@@Base+0x4a8>
   a623d:	mov    0x4084cc(%rip),%rdi        # 4ae710 <curwin@@Base>
   a6244:	test   %ebp,%ebp
   a6246:	jne    a6252 <do_sub@@Base+0x1352>
   a6248:	mov    0x220(%rdi),%ebx
   a624e:	test   %ebx,%ebx
   a6250:	je     a6268 <do_sub@@Base+0x1368>
   a6252:	callq  188c70 <number_width@@Base>
   a6257:	add    $0x1,%eax
   a625a:	add    %eax,0xc0(%rsp)
   a6261:	add    %eax,0xc4(%rsp)
   a6268:	callq  10b440 <msg_start@@Base>
   a626d:	mov    0xc0(%rsp),%r11d
   a6275:	xor    %ebx,%ebx
   a6277:	test   %r11d,%r11d
   a627a:	jle    a62be <do_sub@@Base+0x13be>
   a627c:	nopl   0x0(%rax)
   a6280:	mov    $0x20,%edi
   a6285:	add    $0x1,%rbx
   a6289:	callq  10b430 <msg_putchar@@Base>
   a628e:	movslq 0xc0(%rsp),%rax
   a6296:	cmp    %rbx,%rax
   a6299:	jg     a6280 <do_sub@@Base+0x1380>
   a629b:	movslq 0xc4(%rsp),%rax
   a62a3:	cmp    %rbx,%rax
   a62a6:	jl     a62cb <do_sub@@Base+0x13cb>
   a62a8:	nopl   0x0(%rax,%rax,1)
   a62b0:	mov    $0x5e,%edi
   a62b5:	add    $0x1,%rbx
   a62b9:	callq  10b430 <msg_putchar@@Base>
   a62be:	movslq 0xc4(%rsp),%rax
   a62c6:	cmp    %rbx,%rax
   a62c9:	jge    a62b0 <do_sub@@Base+0x13b0>
   a62cb:	xor    %edx,%edx
   a62cd:	xor    %esi,%esi
   a62cf:	mov    $0x3f,%edi
   a62d4:	callq  c79a0 <getexmodeline@@Base>
   a62d9:	test   %rax,%rax
   a62dc:	je     a6131 <do_sub@@Base+0x1231>
   a62e2:	mov    %rax,%rdi
   a62e5:	movzbl (%rax),%r12d
   a62e9:	callq  11c7f0 <vim_free@@Base>
   a62ee:	jmpq   a6131 <do_sub@@Base+0x1231>
   a62f3:	nopl   0x0(%rax,%rax,1)
   a62f8:	movl   $0x0,0x407bda(%rip)        # 4adedc <msg_didout@@Base>
   a6302:	jmpq   a6064 <do_sub@@Base+0x1164>
   a6307:	nopw   0x0(%rax,%rax,1)
   a6310:	callq  124ea0 <scrollup_clamp@@Base>
   a6315:	jmpq   a5f30 <do_sub@@Base+0x1030>
   a631a:	nopw   0x0(%rax,%rax,1)
   a6320:	mov    (%rsp),%rdi
   a6324:	callq  11c7f0 <vim_free@@Base>
   a6329:	lea    0x17f825(%rip),%rdi        # 225b55 <_IO_stdin_used@@Base+0xf595>
   a6330:	callq  11f220 <vim_strsave@@Base>
   a6335:	movl   $0x0,0x28(%rsp)
   a633d:	mov    %rax,(%rsp)
   a6341:	jmpq   a5d46 <do_sub@@Base+0xe46>
   a6346:	nopw   %cs:0x0(%rax,%rax,1)
   a6350:	lea    0x32(%rbp),%eax
   a6353:	mov    %eax,%edi
   a6355:	mov    %eax,0x70(%rsp)
   a6359:	callq  121d00 <alloc_check@@Base>
   a635e:	test   %rax,%rax
   a6361:	mov    %rax,%rbp
   a6364:	je     a6741 <do_sub@@Base+0x1841>
   a636a:	lea    0x1(%r12),%edx
   a636f:	mov    %r14,%rsi
   a6372:	mov    %rax,%rdi
   a6375:	movslq %edx,%rdx
   a6378:	callq  4f0d0 <_init@@Base+0x4e0>
   a637d:	mov    %r14,%rdi
   a6380:	mov    %rbp,%r14
   a6383:	callq  11c7f0 <vim_free@@Base>
   a6388:	jmpq   a5c77 <do_sub@@Base+0xd77>
   a638d:	nopl   (%rax)
   a6390:	mov    0x88(%rsp),%r13
   a6398:	movl   $0x1,0x68(%rsp)
   a63a0:	mov    0x74(%rsp),%eax
   a63a4:	mov    %eax,0x3fa9c2(%rip)        # 4a0d6c <State@@Base>
   a63aa:	callq  1cd450 <setmouse@@Base>
   a63af:	mov    0x4097b2(%rip),%rdi        # 4afb68 <p_cpo@@Base>
   a63b6:	mov    $0x75,%esi
   a63bb:	callq  11c810 <vim_strchr@@Base>
   a63c0:	test   %rax,%rax
   a63c3:	je     a63cc <do_sub@@Base+0x14cc>
   a63c5:	subl   $0x1,0x4078f0(%rip)        # 4adcbc <no_u_sync@@Base>
   a63cc:	cmp    $0x6e,%r12d
   a63d0:	je     a5aae <do_sub@@Base+0xbae>
   a63d6:	mov    0x68(%rsp),%r9d
   a63db:	test   %r9d,%r9d
   a63de:	jne    a63f8 <do_sub@@Base+0x14f8>
   a63e0:	mov    0x408329(%rip),%rbp        # 4ae710 <curwin@@Base>
   a63e7:	mov    0x3fb9c6(%rip),%r12d        # 4a1db4 <current_funccal@@Base+0x4ac>
   a63ee:	jmpq   a5b06 <do_sub@@Base+0xc06>
   a63f3:	nopl   0x0(%rax,%rax,1)
   a63f8:	xor    %ebx,%ebx
   a63fa:	jmpq   a5835 <do_sub@@Base+0x935>
   a63ff:	mov    0x74(%rsp),%eax
   a6403:	mov    0x88(%rsp),%r13
   a640b:	mov    %eax,0x3fa95b(%rip)        # 4a0d6c <State@@Base>
   a6411:	callq  1cd450 <setmouse@@Base>
   a6416:	mov    0x40974b(%rip),%rdi        # 4afb68 <p_cpo@@Base>
   a641d:	mov    $0x75,%esi
   a6422:	callq  11c810 <vim_strchr@@Base>
   a6427:	test   %rax,%rax
   a642a:	je     a6c3b <do_sub@@Base+0x1d3b>
   a6430:	subl   $0x1,0x407885(%rip)        # 4adcbc <no_u_sync@@Base>
   a6437:	xor    %ebx,%ebx
   a6439:	movl   $0x1,0x68(%rsp)
   a6441:	jmpq   a5835 <do_sub@@Base+0x935>
   a6446:	movl   $0x1,0x2c(%rsp)
   a644e:	mov    $0x1,%r12d
   a6454:	mov    $0xffffffffffffffff,%r13
   a645b:	jmpq   a58d6 <do_sub@@Base+0x9d6>
   a6460:	xor    %edi,%edi
   a6462:	cmp    $0xffffffffffffffff,%r13
   a6466:	je     a66d9 <do_sub@@Base+0x17d9>
   a646c:	mov    0x48(%rsp),%r13d
   a6471:	test   %r13d,%r13d
   a6474:	je     a647e <do_sub@@Base+0x157e>
   a6476:	addq   $0x1,0x408fc2(%rip)        # 4af440 <sub_nlines@@Base>
   a647e:	callq  11c7f0 <vim_free@@Base>
   a6483:	mov    (%rsp),%rdi
   a6487:	mov    $0x1,%ebx
   a648c:	callq  11c7f0 <vim_free@@Base>
   a6491:	mov    0x68(%rsp),%r12d
   a6496:	test   %r12d,%r12d
   a6499:	sete   %bpl
   a649d:	callq  119f10 <line_breakcheck@@Base>
   a64a2:	add    $0x1,%r15
   a64a6:	cmp    %r15,0x38(%rsp)
   a64ab:	jl     a64b6 <do_sub@@Base+0x15b6>
   a64ad:	test   %bpl,%bpl
   a64b0:	jne    a56d8 <do_sub@@Base+0x7d8>
   a64b6:	cmpq   $0x0,0x40(%rsp)
   a64bc:	movq   $0x0,(%rsp)
   a64c4:	je     a64ec <do_sub@@Base+0x15ec>
   a64c6:	mov    0x4078ab(%rip),%rax        # 4add78 <curbuf@@Base>
   a64cd:	mov    0x60(%rsp),%rdx
   a64d2:	xor    %esi,%esi
   a64d4:	mov    0x40(%rsp),%rdi
   a64d9:	mov    (%rax),%rcx
   a64dc:	sub    0xa0(%rsp),%rcx
   a64e4:	sub    %rcx,%rdx
   a64e7:	callq  111a20 <changed_lines@@Base>
   a64ec:	mov    (%rsp),%rdi
   a64f0:	callq  11c7f0 <vim_free@@Base>
   a64f5:	mov    0x3fb8b9(%rip),%edi        # 4a1db4 <current_funccal@@Base+0x4ac>
   a64fb:	test   %edi,%edi
   a64fd:	je     a6526 <do_sub@@Base+0x1626>
   a64ff:	mov    0x40820a(%rip),%rax        # 4ae710 <curwin@@Base>
   a6506:	mov    0xb0(%rsp),%rcx
   a650e:	mov    0xb8(%rsp),%edx
   a6515:	mov    %rcx,0x38(%rax)
   a6519:	mov    0xac(%rsp),%ecx
   a6520:	mov    %edx,0x40(%rax)
   a6523:	mov    %ecx,0x44(%rax)
   a6526:	movslq 0x9c(%rsp),%rax
   a652e:	cmp    0x40908b(%rip),%rax        # 4af5c0 <sub_nsubs@@Base>
   a6535:	jge    a6753 <do_sub@@Base+0x1853>
   a653b:	mov    0x90(%rsp),%rdx
   a6543:	mov    0x407687(%rip),%ebp        # 4adbd0 <global_busy@@Base>
   a6549:	mov    0x407828(%rip),%rax        # 4add78 <curbuf@@Base>
   a6550:	mov    0x38(%rsp),%rcx
   a6555:	mov    0x40(%rdx),%rdx
   a6559:	test   %ebp,%ebp
   a655b:	mov    %rcx,0x11c0(%rax)
   a6562:	movl   $0x0,0x11c8(%rax)
   a656c:	movl   $0x0,0x11a8(%rax)
   a6576:	mov    %rdx,0x11a0(%rax)
   a657d:	jne    a67f1 <do_sub@@Base+0x18f1>
   a6583:	mov    0x3fb833(%rip),%ebx        # 4a1dbc <current_funccal@@Base+0x4b4>
   a6589:	test   %ebx,%ebx
   a658b:	jne    a65ae <do_sub@@Base+0x16ae>
   a658d:	mov    0x98(%rsp),%r11d
   a6595:	test   %r11d,%r11d
   a6598:	je     a6864 <do_sub@@Base+0x1964>
   a659e:	mov    $0x7fffffff,%edi
   a65a3:	callq  11f020 <coladvance@@Base>
   a65a8:	mov    0x3fb806(%rip),%edi        # 4a1db4 <current_funccal@@Base+0x4ac>
   a65ae:	callq  a4ce0 <do_sub_msg@@Base>
   a65b3:	test   %eax,%eax
   a65b5:	jne    a67fb <do_sub@@Base+0x18fb>
   a65bb:	mov    0x3fb7fa(%rip),%r10d        # 4a1dbc <current_funccal@@Base+0x4b4>
   a65c2:	test   %r10d,%r10d
   a65c5:	jne    a6883 <do_sub@@Base+0x1983>
   a65cb:	mov    0x3fb7e7(%rip),%edx        # 4a1db8 <current_funccal@@Base+0x4b0>
   a65d1:	test   %edx,%edx
   a65d3:	jne    a6807 <do_sub@@Base+0x1907>
   a65d9:	mov    0xd0(%rsp),%rdi
   a65e1:	callq  17fe70 <vim_regfree@@Base>
   a65e6:	mov    0xa8(%rsp),%eax
   a65ed:	mov    %eax,0x3fb7cd(%rip)        # 4a1dc0 <current_funccal@@Base+0x4b8>
   a65f3:	mov    0xbc(%rsp),%eax
   a65fa:	mov    %eax,0x3fb7bc(%rip)        # 4a1dbc <current_funccal@@Base+0x4b4>
   a6600:	jmpq   a55ba <do_sub@@Base+0x6ba>
   a6605:	mov    0x88(%rsp),%r13
   a660d:	mov    0x74(%rsp),%eax
   a6611:	mov    %eax,0x3fa755(%rip)        # 4a0d6c <State@@Base>
   a6617:	callq  1cd450 <setmouse@@Base>
   a661c:	mov    0x409545(%rip),%rdi        # 4afb68 <p_cpo@@Base>
   a6623:	mov    $0x75,%esi
   a6628:	callq  11c810 <vim_strchr@@Base>
   a662d:	test   %rax,%rax
   a6630:	jne    a63c5 <do_sub@@Base+0x14c5>
   a6636:	jmpq   a63d6 <do_sub@@Base+0x14d6>
   a663b:	mov    0x88(%rsp),%r13
   a6643:	movl   $0x0,0x3fb773(%rip)        # 4a1dc0 <current_funccal@@Base+0x4b8>
   a664d:	mov    %r15,0x38(%rsp)
   a6652:	jmp    a660d <do_sub@@Base+0x170d>
   a6654:	mov    0x88(%rsp),%r13
   a665c:	movl   $0x0,0x3fb756(%rip)        # 4a1dbc <current_funccal@@Base+0x4b4>
   a6666:	jmp    a660d <do_sub@@Base+0x170d>
   a6668:	mov    $0x1,%ebp
   a666d:	jmpq   a649d <do_sub@@Base+0x159d>
   a6672:	lea    0x32(%rbp),%eax
   a6675:	mov    %eax,%edi
   a6677:	mov    %eax,0x70(%rsp)
   a667b:	callq  121d00 <alloc_check@@Base>
   a6680:	test   %rax,%rax
   a6683:	mov    %rax,%r10
   a6686:	je     a6879 <do_sub@@Base+0x1979>
   a668c:	movb   $0x0,(%rax)
   a668f:	mov    %rax,%r14
   a6692:	jmpq   a5c7d <do_sub@@Base+0xd7d>
   a6697:	mov    %r14,%rdi
   a669a:	jmpq   a646c <do_sub@@Base+0x156c>
   a669f:	callq  f8ff0 <setpcmark@@Base>
   a66a4:	jmpq   a571a <do_sub@@Base+0x81a>
   a66a9:	mov    0x50(%rsp),%rdi
   a66ae:	mov    $0x1,%esi
   a66b3:	callq  111be0 <appended_lines@@Base>
   a66b8:	jmpq   a5e4d <do_sub@@Base+0xf4d>
   a66bd:	mov    %r14,%rdi
   a66c0:	mov    %rbx,%r15
   a66c3:	jmpq   a646c <do_sub@@Base+0x156c>
   a66c8:	callq  *0x3fa97a(%rip)        # 4a1048 <mb_ptr2len@@Base>
   a66ce:	xor    %ebx,%ebx
   a66d0:	add    %eax,0x8(%rsp)
   a66d4:	jmpq   a5835 <do_sub@@Base+0x935>
   a66d9:	sub    0xd8(%rsp),%r15
   a66e1:	jmpq   a646c <do_sub@@Base+0x156c>
   a66e6:	mov    0xd0(%rsp),%rdi
   a66ee:	callq  17f3b0 <re_multiline@@Base>
   a66f3:	test   %eax,%eax
   a66f5:	je     a5ad0 <do_sub@@Base+0xbd0>
   a66fb:	jmpq   a588b <do_sub@@Base+0x98b>
   a6700:	mov    0x90(%rsp),%rdx
   a6708:	mov    0x30(%rdx),%ecx
   a670b:	test   %ecx,%ecx
   a670d:	jne    a5218 <do_sub@@Base+0x318>
   a6713:	mov    0x3e754f(%rip),%edx        # 48dc68 <__data_start@@Base+0x4c68>
   a6719:	test   %edx,%edx
   a671b:	je     a5218 <do_sub@@Base+0x318>
   a6721:	lea    0x3f9888(%rip),%rsi        # 49ffb0 <e_zerocount@@Base>
   a6728:	xor    %edi,%edi
   a672a:	mov    $0x5,%edx
   a672f:	callq  4ed78 <_init@@Base+0x188>
   a6734:	mov    %rax,%rdi
   a6737:	callq  10d330 <emsg@@Base>
   a673c:	jmpq   a55ba <do_sub@@Base+0x6ba>
   a6741:	mov    %r14,%rdi
   a6744:	mov    $0x1,%ebx
   a6749:	callq  11c7f0 <vim_free@@Base>
   a674e:	jmpq   a64ec <do_sub@@Base+0x15ec>
   a6753:	mov    0x407476(%rip),%r8d        # 4adbd0 <global_busy@@Base>
   a675a:	test   %r8d,%r8d
   a675d:	jne    a67a5 <do_sub@@Base+0x18a5>
   a675f:	mov    0x40749b(%rip),%eax        # 4adc00 <got_int@@Base>
   a6765:	test   %eax,%eax
   a6767:	jne    a68a5 <do_sub@@Base+0x19a5>
   a676d:	test   %ebx,%ebx
   a676f:	jne    a6894 <do_sub@@Base+0x1994>
   a6775:	mov    0x3e74ed(%rip),%edi        # 48dc68 <__data_start@@Base+0x4c68>
   a677b:	test   %edi,%edi
   a677d:	je     a67a5 <do_sub@@Base+0x18a5>
   a677f:	callq  1927a0 <get_search_pat@@Base>
   a6784:	lea    0x3f9cd5(%rip),%rsi        # 4a0460 <e_patnotf2@@Base>
   a678b:	mov    %rax,%rbx
   a678e:	xor    %edi,%edi
   a6790:	mov    $0x5,%edx
   a6795:	callq  4ed78 <_init@@Base+0x188>
   a679a:	mov    %rbx,%rsi
   a679d:	mov    %rax,%rdi
   a67a0:	callq  107390 <emsg2@@Base>
   a67a5:	mov    0x3fb611(%rip),%esi        # 4a1dbc <current_funccal@@Base+0x4b4>
   a67ab:	test   %esi,%esi
   a67ad:	je     a65d9 <do_sub@@Base+0x16d9>
   a67b3:	mov    0x407f56(%rip),%rdi        # 4ae710 <curwin@@Base>
   a67ba:	callq  e3890 <hasAnyFolding@@Base>
   a67bf:	test   %eax,%eax
   a67c1:	je     a65d9 <do_sub@@Base+0x16d9>
   a67c7:	callq  122900 <changed_window_setting@@Base>
   a67cc:	jmpq   a65d9 <do_sub@@Base+0x16d9>
   a67d1:	lea    0x3fa0a8(%rip),%rsi        # 4a0880 <e_modifiable@@Base>
   a67d8:	xor    %edi,%edi
   a67da:	mov    $0x5,%edx
   a67df:	callq  4ed78 <_init@@Base+0x188>
   a67e4:	mov    %rax,%rdi
   a67e7:	callq  10d330 <emsg@@Base>
   a67ec:	jmpq   a55ba <do_sub@@Base+0x6ba>
   a67f1:	movl   $0x1,0x3fb5d5(%rip)        # 4a1dd0 <current_funccal@@Base+0x4c8>
   a67fb:	mov    0x3fb5b6(%rip),%r9d        # 4a1db8 <current_funccal@@Base+0x4b0>
   a6802:	test   %r9d,%r9d
   a6805:	je     a67a5 <do_sub@@Base+0x18a5>
   a6807:	mov    0x407f02(%rip),%rax        # 4ae710 <curwin@@Base>
   a680e:	mov    0x3fb594(%rip),%edx        # 4a1da8 <current_funccal@@Base+0x4a0>
   a6814:	mov    0x3fb596(%rip),%esi        # 4a1db0 <current_funccal@@Base+0x4a8>
   a681a:	mov    0x38(%rax),%rdi
   a681e:	callq  a1a40 <print_line@@Base>
   a6823:	jmp    a67a5 <do_sub@@Base+0x18a5>
   a6825:	movl   $0x1,0x218(%rsp)
   a6830:	jmpq   a5658 <do_sub@@Base+0x758>
   a6835:	movl   $0x0,0x218(%rsp)
   a6840:	jmpq   a5658 <do_sub@@Base+0x758>
   a6845:	mov    0x3fb571(%rip),%eax        # 4a1dbc <current_funccal@@Base+0x4b4>
   a684b:	mov    %eax,0xbc(%rsp)
   a6852:	mov    0x3fb568(%rip),%eax        # 4a1dc0 <current_funccal@@Base+0x4b8>
   a6858:	mov    %eax,0xa8(%rsp)
   a685f:	jmpq   a51ea <do_sub@@Base+0x2ea>
   a6864:	mov    $0x5,%edi
   a6869:	callq  6a2f0 <beginline@@Base>
   a686e:	mov    0x3fb540(%rip),%edi        # 4a1db4 <current_funccal@@Base+0x4ac>
   a6874:	jmpq   a65ae <do_sub@@Base+0x16ae>
   a6879:	mov    $0x1,%ebx
   a687e:	jmpq   a64ec <do_sub@@Base+0x15ec>
   a6883:	lea    0x17f2cb(%rip),%rdi        # 225b55 <_IO_stdin_used@@Base+0xf595>
   a688a:	callq  10d1f0 <msg@@Base>
   a688f:	jmpq   a67fb <do_sub@@Base+0x18fb>
   a6894:	lea    0x17f2ba(%rip),%rdi        # 225b55 <_IO_stdin_used@@Base+0xf595>
   a689b:	callq  10d1f0 <msg@@Base>
   a68a0:	jmpq   a67a5 <do_sub@@Base+0x18a5>
   a68a5:	lea    0x3fa1dc(%rip),%rsi        # 4a0a88 <e_interr@@Base>
   a68ac:	xor    %edi,%edi
   a68ae:	mov    $0x5,%edx
   a68b3:	callq  4ed78 <_init@@Base+0x188>
   a68b8:	mov    %rax,%rdi
   a68bb:	callq  10d330 <emsg@@Base>
   a68c0:	jmpq   a67a5 <do_sub@@Base+0x18a5>
   a68c5:	callq  *0x3fa77d(%rip)        # 4a1048 <mb_ptr2len@@Base>
   a68cb:	mov    0xc8(%rsp),%rdi
   a68d3:	cltq   
   a68d5:	jmpq   a5535 <do_sub@@Base+0x635>
   a68da:	mov    %rbx,0x20(%rsp)
   a68df:	mov    0x90(%rsp),%rax
   a68e7:	mov    0x30(%rax),%r13d
   a68eb:	test   %r13d,%r13d
   a68ee:	jne    a6932 <do_sub@@Base+0x1a32>
   a68f0:	cmpb   $0x25,(%rbx)
   a68f3:	jne    a6af5 <do_sub@@Base+0x1bf5>
   a68f9:	cmpb   $0x0,0x1(%rbx)
   a68fd:	jne    a6af5 <do_sub@@Base+0x1bf5>
   a6903:	mov    0x40925e(%rip),%rdi        # 4afb68 <p_cpo@@Base>
   a690a:	mov    $0x2f,%esi
   a690f:	callq  11c810 <vim_strchr@@Base>
   a6914:	test   %rax,%rax
   a6917:	je     a6af5 <do_sub@@Base+0x1bf5>
   a691d:	mov    0x3fb4b4(%rip),%rax        # 4a1dd8 <current_funccal@@Base+0x4d0>
   a6924:	test   %rax,%rax
   a6927:	mov    %rax,0x20(%rsp)
   a692c:	je     a559f <do_sub@@Base+0x69f>
   a6932:	test   %r12,%r12
   a6935:	je     a6a7a <do_sub@@Base+0x1b7a>
   a693b:	cmpb   $0x5c,(%r12)
   a6940:	jne    a6a7a <do_sub@@Base+0x1b7a>
   a6946:	cmpb   $0x6e,0x1(%r12)
   a694c:	jne    a6a7a <do_sub@@Base+0x1b7a>
   a6952:	cmpb   $0x0,0x2(%r12)
   a6958:	jne    a6a7a <do_sub@@Base+0x1b7a>
   a695e:	mov    0x20(%rsp),%rax
   a6963:	mov    0xc8(%rsp),%rdi
   a696b:	cmpb   $0x0,(%rax)
   a696e:	movzbl (%rdi),%eax
   a6971:	jne    a6a95 <do_sub@@Base+0x1b95>
   a6977:	test   %al,%al
   a6979:	je     a69ad <do_sub@@Base+0x1aad>
   a697b:	cmpb   $0x0,0x1(%rdi)
   a697f:	jne    a6a95 <do_sub@@Base+0x1b95>
   a6985:	cmp    $0x23,%al
   a6987:	sete   %cl
   a698a:	cmp    $0x67,%al
   a698c:	sete   %dl
   a698f:	or     %dl,%cl
   a6991:	jne    a69ad <do_sub@@Base+0x1aad>
   a6993:	lea    -0x6c(%rax),%edx
   a6996:	movl   $0x0,0x98(%rsp)
   a69a1:	and    $0xfb,%edx
   a69a7:	jne    a500a <do_sub@@Base+0x10a>
   a69ad:	mov    0x90(%rsp),%rax
   a69b5:	mov    0x40(%rax),%rdx
   a69b9:	mov    0x407d50(%rip),%rax        # 4ae710 <curwin@@Base>
   a69c0:	mov    %rdx,0x38(%rax)
   a69c4:	movzbl (%rdi),%eax
   a69c7:	cmp    $0x6c,%al
   a69c9:	je     a6aba <do_sub@@Base+0x1bba>
   a69cf:	cmp    $0x23,%al
   a69d1:	je     a6ace <do_sub@@Base+0x1bce>
   a69d7:	cmp    $0x70,%al
   a69d9:	jne    a69ea <do_sub@@Base+0x1aea>
   a69db:	mov    0x90(%rsp),%rax
   a69e3:	movl   $0x4,0x54(%rax)
   a69ea:	mov    0x90(%rsp),%r14
   a69f2:	xor    %ebx,%ebx
   a69f4:	mov    0x48(%r14),%rax
   a69f8:	mov    %rax,%rcx
   a69fb:	sub    %rdx,%rcx
   a69fe:	mov    %rcx,%rdx
   a6a01:	mov    0x407370(%rip),%rcx        # 4add78 <curbuf@@Base>
   a6a08:	cmp    (%rcx),%rax
   a6a0b:	setl   %bl
   a6a0e:	lea    0x1(%rbx,%rdx,1),%rbx
   a6a13:	cmp    $0x1,%rbx
   a6a17:	jle    a6a55 <do_sub@@Base+0x1b55>
   a6a19:	mov    %rbx,%rdi
   a6a1c:	mov    $0x1,%r8d
   a6a22:	xor    %ecx,%ecx
   a6a24:	mov    $0x1,%edx
   a6a29:	xor    %esi,%esi
   a6a2b:	sub    $0x1,%rbx
   a6a2f:	callq  140050 <do_join@@Base>
   a6a34:	xor    %edi,%edi
   a6a36:	mov    %rbx,0x408b83(%rip)        # 4af5c0 <sub_nsubs@@Base>
   a6a3d:	movq   $0x1,0x4089f8(%rip)        # 4af440 <sub_nlines@@Base>
   a6a48:	callq  a4ce0 <do_sub_msg@@Base>
   a6a4d:	mov    %r14,%rdi
   a6a50:	callq  b96a0 <ex_may_print@@Base>
   a6a55:	mov    0x4085a8(%rip),%r10d        # 4af004 <cmdmod@@Base+0x24>
   a6a5c:	test   %r10d,%r10d
   a6a5f:	je     a6aa5 <do_sub@@Base+0x1ba5>
   a6a61:	xor    %ecx,%ecx
   a6a63:	mov    $0x1,%edx
   a6a68:	mov    %r12,%rsi
   a6a6b:	mov    $0x1,%edi
   a6a70:	callq  cb240 <add_to_history@@Base>
   a6a75:	jmpq   a55ba <do_sub@@Base+0x6ba>
   a6a7a:	mov    0xc8(%rsp),%rdi
   a6a82:	movzbl (%rdi),%eax
   a6a85:	movl   $0x0,0x98(%rsp)
   a6a90:	jmpq   a500a <do_sub@@Base+0x10a>
   a6a95:	movl   $0x0,0x98(%rsp)
   a6aa0:	jmpq   a500a <do_sub@@Base+0x10a>
   a6aa5:	mov    0x408af5(%rip),%edx        # 4af5a0 <p_magic@@Base>
   a6aab:	mov    %r12,%rsi
   a6aae:	mov    $0x1,%edi
   a6ab3:	callq  192870 <save_re_pat@@Base>
   a6ab8:	jmp    a6a61 <do_sub@@Base+0x1b61>
   a6aba:	mov    0x90(%rsp),%rax
   a6ac2:	movl   $0x1,0x54(%rax)
   a6ac9:	jmpq   a69ea <do_sub@@Base+0x1aea>
   a6ace:	mov    0x90(%rsp),%rax
   a6ad6:	movl   $0x2,0x54(%rax)
   a6add:	jmpq   a69ea <do_sub@@Base+0x1aea>
   a6ae2:	mov    0x90(%rsp),%rax
   a6aea:	mov    0x30(%rax),%eax
   a6aed:	test   %eax,%eax
   a6aef:	jne    a6932 <do_sub@@Base+0x1a32>
   a6af5:	mov    0x3fb2dc(%rip),%rdi        # 4a1dd8 <current_funccal@@Base+0x4d0>
   a6afc:	callq  11c7f0 <vim_free@@Base>
   a6b01:	mov    0x20(%rsp),%rdi
   a6b06:	callq  11f220 <vim_strsave@@Base>
   a6b0b:	mov    %rax,0x3fb2c6(%rip)        # 4a1dd8 <current_funccal@@Base+0x4d0>
   a6b12:	jmpq   a6932 <do_sub@@Base+0x1a32>
   a6b17:	mov    0x20(%rsp),%rdx
   a6b1c:	mov    $0x2,%ebp
   a6b21:	mov    %rdx,%rax
   a6b24:	add    $0x1,%rax
   a6b28:	mov    %rax,0xc8(%rsp)
   a6b30:	movb   $0x0,(%rdx)
   a6b33:	mov    0xc8(%rsp),%rax
   a6b3b:	mov    %rax,0x20(%rsp)
   a6b40:	mov    0x20(%rsp),%rdi
   a6b45:	movzbl (%rdi),%eax
   a6b48:	test   %al,%al
   a6b4a:	je     a6ae2 <do_sub@@Base+0x1be2>
   a6b4c:	movzbl %al,%edx
   a6b4f:	cmp    %edx,%r13d
   a6b52:	je     a6b82 <do_sub@@Base+0x1c82>
   a6b54:	mov    %rdi,%rbx
   a6b57:	jmpq   a5557 <do_sub@@Base+0x657>
   a6b5c:	mov    %rdi,0x20(%rsp)
   a6b61:	mov    0x20(%rsp),%rdx
   a6b66:	mov    %rbx,0x20(%rsp)
   a6b6b:	mov    %rdx,%rax
   a6b6e:	add    $0x1,%rax
   a6b72:	mov    %rax,0xc8(%rsp)
   a6b7a:	movb   $0x0,(%rdx)
   a6b7d:	jmpq   a68df <do_sub@@Base+0x19df>
   a6b82:	mov    0x20(%rsp),%rbx
   a6b87:	jmp    a6b61 <do_sub@@Base+0x1c61>
   a6b89:	mov    %ecx,0x3fb22d(%rip)        # 4a1dbc <current_funccal@@Base+0x4b4>
   a6b8f:	jmpq   a5373 <do_sub@@Base+0x473>
   a6b94:	callq  4ed90 <_init@@Base+0x1a0>
   a6b99:	movq   $0x0,(%rsp)
   a6ba1:	jmpq   a64ec <do_sub@@Base+0x15ec>
   a6ba6:	lea    0x1(%rdi),%rax
   a6baa:	mov    %rax,0xc8(%rsp)
   a6bb2:	movzbl 0x1(%rdi),%esi
   a6bb6:	lea    0x174849(%rip),%rdi        # 21b406 <_IO_stdin_used@@Base+0x4e46>
   a6bbd:	callq  11c810 <vim_strchr@@Base>
   a6bc2:	test   %rax,%rax
   a6bc5:	je     a6c1b <do_sub@@Base+0x1d1b>
   a6bc7:	mov    0xc8(%rsp),%rax
   a6bcf:	mov    $0x0,%edx
   a6bd4:	lea    0x17ef7a(%rip),%r12        # 225b55 <_IO_stdin_used@@Base+0xf595>
   a6bdb:	cmpb   $0x26,(%rax)
   a6bde:	cmovne %edx,%ebp
   a6be1:	lea    0x1(%rax),%rdx
   a6be5:	mov    %rdx,0xc8(%rsp)
   a6bed:	mov    %rdx,0x20(%rsp)
   a6bf2:	movzbl (%rax),%r13d
   a6bf6:	jmpq   a6b40 <do_sub@@Base+0x1c40>
   a6bfb:	lea    0x174f76(%rip),%rsi        # 21bb78 <_IO_stdin_used@@Base+0x55b8>
   a6c02:	xor    %edi,%edi
   a6c04:	mov    $0x5,%edx
   a6c09:	callq  4ed78 <_init@@Base+0x188>
   a6c0e:	mov    %rax,%rdi
   a6c11:	callq  10d330 <emsg@@Base>
   a6c16:	jmpq   a55ba <do_sub@@Base+0x6ba>
   a6c1b:	lea    0x3fa07e(%rip),%rsi        # 4a0ca0 <e_backslash@@Base>
   a6c22:	xor    %edi,%edi
   a6c24:	mov    $0x5,%edx
   a6c29:	callq  4ed78 <_init@@Base+0x188>
   a6c2e:	mov    %rax,%rdi
   a6c31:	callq  10d330 <emsg@@Base>
   a6c36:	jmpq   a55ba <do_sub@@Base+0x6ba>
   a6c3b:	xor    %ebx,%ebx
   a6c3d:	movl   $0x1,0x68(%rsp)
   a6c45:	jmpq   a5835 <do_sub@@Base+0x935>
   a6c4a:	xor    %r12d,%r12d
   a6c4d:	mov    $0xffffffffffffffff,%r13
   a6c54:	jmpq   a58d6 <do_sub@@Base+0x9d6>
   a6c59:	nopl   0x0(%rax)
