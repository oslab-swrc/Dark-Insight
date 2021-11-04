// TC_OUT _process_task_wait_loop,0x408817,0x408850,-0x4(%rbp),-0x8(%rbp)
0000000000408800 <_process_task_wait_loop>:
	408800:	   push   %rbp
	408801:	   mov    %rsp,%rbp
	408804:	   mov    %edi,-0x14(%rbp)
	408807:	   movl   $0x0,-0x4(%rbp)
	40880e:	   movl   $0x0,-0x8(%rbp)
	408815:	   jmp    408843 <_process_task_wait_loop+0x43>
	408817:	   mov    -0x8(%rbp),%eax
	40881a:	   movzbl %al,%eax
	40881d:	   test   %eax,%eax
	40881f:	   jne    40883f <_process_task_wait_loop+0x3f>
	408821:	   mov    0x218020(%rip),%rax        # 620848 <global>
	408828:	   mov    0x295d48(%rax),%edx
	40882e:	   mov    0x20d94c(%rip),%eax        # 616180 <n_processors>
	408834:	   cmp    %eax,%edx
	408836:	   jl     40883f <_process_task_wait_loop+0x3f>
	408838:	   movl   $0x1,-0x4(%rbp)
	40883f:	   addl   $0x1,-0x8(%rbp)
	408843:	   cmpl   $0x3e7,-0x8(%rbp)
	40884a:	   jg     408852 <_process_task_wait_loop+0x52>
	40884c:	   cmpl   $0x0,-0x4(%rbp)
	408850:	   je     408817 <_process_task_wait_loop+0x17>
	408852:	   mov    -0x4(%rbp),%eax
	408855:	   pop    %rbp
	408856:	   retq
