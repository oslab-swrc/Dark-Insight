// TC_OUT
00000000000a9270 <gtk_color_selection_palette_to_string>:
   a9270:	test   %esi,%esi
   a9272:	je     a9343 <gtk_color_selection_palette_to_string+0xd3>
   a9278:	push   %r13
   a927a:	push   %r12
   a927c:	mov    %esi,%r12d
   a927f:	push   %rbp
   a9280:	push   %rbx
   a9281:	mov    %rdi,%rbx
   a9284:	lea    0x1(%rsi),%edi
   a9287:	mov    $0x8,%esi
   a928c:	sub    $0x8,%rsp
   a9290:	movslq %edi,%rdi
   a9293:	callq  7a1e0 <g_malloc0_n@plt>
   a9298:	test   %r12d,%r12d
   a929b:	mov    %rax,%r13
   a929e:	jle    a931b <gtk_color_selection_palette_to_string+0xab>
   a92a0:	mov    %rax,%rbp
   a92a3:	lea    -0x1(%r12),%eax
   a92a8:	add    $0x6,%rbx
   a92ac:	lea    0x8(,%rax,8),%r12
   a92b4:	add    %r13,%r12
   a92b7:	nopw   0x0(%rax,%rax,1)
   a92c0:	movzwl (%rbx),%edx
   a92c3:	movzbl 0x3(%rbx),%ecx
   a92c7:	lea    0x2d3718(%rip),%rdi        # 37c9e6 <_fini+0x49aa>
   a92ce:	movzbl -0x1(%rbx),%esi
   a92d2:	xor    %eax,%eax
   a92d4:	movzbl %dh,%edx
   a92d7:	callq  7a6d0 <g_strdup_printf@plt>
   a92dc:	mov    %rax,0x0(%rbp)
   a92e0:	movzbl (%rax),%ecx
   a92e3:	test   %cl,%cl
   a92e5:	jne    a92fb <gtk_color_selection_palette_to_string+0x8b>
   a92e7:	jmp    a930e <gtk_color_selection_palette_to_string+0x9e>
   a92e9:	nopl   0x0(%rax)
   a92f0:	add    $0x1,%rax
   a92f4:	movzbl (%rax),%ecx
   a92f7:	test   %cl,%cl
   a92f9:	je     a930e <gtk_color_selection_palette_to_string+0x9e>
   a92fb:	cmp    $0x20,%cl
   a92fe:	jne    a92f0 <gtk_color_selection_palette_to_string+0x80>
   a9300:	movb   $0x30,(%rax)
   a9303:	add    $0x1,%rax
   a9307:	movzbl (%rax),%ecx
   a930a:	test   %cl,%cl
   a930c:	jne    a92fb <gtk_color_selection_palette_to_string+0x8b>
   a930e:	add    $0x8,%rbp
   a9312:	add    $0xc,%rbx
   a9316:	cmp    %r12,%rbp
   a9319:	jne    a92c0 <gtk_color_selection_palette_to_string+0x50>
   a931b:	lea    0x352495(%rip),%rdi        # 3fb7b7 <_fini+0x8377b>
   a9322:	mov    %r13,%rsi
   a9325:	callq  7cb90 <g_strjoinv@plt>
   a932a:	mov    %r13,%rdi
   a932d:	mov    %rax,%rbx
   a9330:	callq  7e510 <g_strfreev@plt>
   a9335:	add    $0x8,%rsp
   a9339:	mov    %rbx,%rax
   a933c:	pop    %rbx
   a933d:	pop    %rbp
   a933e:	pop    %r12
   a9340:	pop    %r13
   a9342:	retq   
   a9343:	lea    0x33b671(%rip),%rdi        # 3e49bb <_fini+0x6c97f>
   a934a:	jmpq   78b10 <g_strdup@plt>
   a934f:	nop
   a9350:	push   %rbp
   a9351:	push   %rbx
   a9352:	mov    %rdi,%rbp
   a9355:	mov    %rsi,%rdi
   a9358:	mov    %edx,%esi
   a935a:	sub    $0x8,%rsp
   a935e:	callq  a9270 <gtk_color_selection_palette_to_string>
   a9363:	mov    %rbp,%rdi
   a9366:	mov    %rax,%rbx
   a9369:	callq  2706c0 <gtk_settings_get_for_screen>
   a936e:	lea    0x2d3613(%rip),%rcx        # 37c988 <_fini+0x494c>
   a9375:	lea    0x2d399f(%rip),%rsi        # 37cd1b <_fini+0x4cdf>
   a937c:	mov    %rbx,%rdx
   a937f:	mov    %rax,%rdi
   a9382:	callq  273b40 <gtk_settings_set_string_property>
   a9387:	add    $0x8,%rsp
   a938b:	mov    %rbx,%rdi
   a938e:	pop    %rbx
   a938f:	pop    %rbp
   a9390:	jmpq   77940 <g_free@plt>
   a9395:	nop
   a9396:	nopw   %cs:0x0(%rax,%rax,1)
   a93a0:	push   %rbp
   a93a1:	push   %rbx
   a93a2:	mov    %esi,%ebp
   a93a4:	mov    %rdi,%rbx
   a93a7:	sub    $0x8,%rsp
   a93ab:	callq  7edd0 <gdk_screen_get_default@plt>
   a93b0:	add    $0x8,%rsp
   a93b4:	mov    %ebp,%edx
   a93b6:	mov    %rbx,%rsi
   a93b9:	pop    %rbx
   a93ba:	pop    %rbp
   a93bb:	mov    %rax,%rdi
   a93be:	jmp    a9350 <gtk_color_selection_palette_to_string+0xe0>
