// Bitcoin Hashing without iterations (possibly limited by FPGAs)
module bitcoin_hash_no_itr(input logic        clk, reset_n, start,
                    input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                    input logic [31:0] mem_read_data);

// Number of NONCES
parameter integer NUM_OF_NONCES=16;

// Local Variables
logic [31:0] w[NUM_OF_NONCES][16];
logic [31:0] message[20];
logic [31:0] A[NUM_OF_NONCES], B[NUM_OF_NONCES], C[NUM_OF_NONCES], D[NUM_OF_NONCES], E[NUM_OF_NONCES], F[NUM_OF_NONCES], G[NUM_OF_NONCES], H[NUM_OF_NONCES];
logic [31:0] h0[NUM_OF_NONCES], h1[NUM_OF_NONCES], h2[NUM_OF_NONCES], h3[NUM_OF_NONCES], h4[NUM_OF_NONCES], h5[NUM_OF_NONCES], h6[NUM_OF_NONCES], h7[NUM_OF_NONCES];
logic [31:0] h0_const, h1_const, h2_const, h3_const, h4_const, h5_const, h6_const, h7_const;
logic [31:0] h0_out_phase1, h1_out_phase1, h2_out_phase1, h3_out_phase1, h4_out_phase1, h5_out_phase1, h6_out_phase1, h7_out_phase1;
logic [31:0] h0_out[NUM_OF_NONCES], h1_out[NUM_OF_NONCES], h2_out[NUM_OF_NONCES], h3_out[NUM_OF_NONCES], h4_out[NUM_OF_NONCES], h5_out[NUM_OF_NONCES], h6_out[NUM_OF_NONCES], h7_out[NUM_OF_NONCES];
integer i;
logic [15:0] offset;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [31:0] nonce_value;

// FSM state variables 
enum logic [3:0] {IDLE, READ, PHASE1_BLOCK, PHASE1_COMPUTE, PHASE2_BLOCK, PHASE2_COMPUTE, PHASE3_BLOCK, PHASE3_COMPUTE, WRITE} state;

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

function logic [31:0] wtnew(input logic [15:0] n, logic[7:0] t);
 logic [31:0] s1, s0;
 s0 = rightrotate(w[n][t-15], 7) ^ rightrotate(w[n][t-15], 18) ^ (w[n][t-15] >> 3);
 s1 = rightrotate(w[n][t-2], 17) ^ rightrotate(w[n][t-2], 19) ^ (w[n][t-2] >> 10);
 wtnew = w[n][t-16] + s0 + w[n][t-7] + s1;
endfunction

// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;

// Setting Initial Hash Values
assign h0_const = 32'h6a09e667;
assign h1_const = 32'hbb67ae85;
assign h2_const = 32'h3c6ef372;
assign h3_const = 32'ha54ff53a;
assign h4_const = 32'h510e527f;
assign h5_const = 32'h9b05688c;
assign h6_const = 32'h1f83d9ab;
assign h7_const = 32'h5be0cd19;

// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction


// FSM Implementation
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
       if(start) begin
		  for(int n=0; n<NUM_OF_NONCES; n++) begin
	       		h0[n] <= h0_const;
			h1[n] <= h1_const;
			h2[n] <= h2_const;
			h3[n] <= h3_const;
			h4[n] <= h4_const;
			h5[n] <= h5_const;
			h6[n] <= h6_const;
			h7[n] <= h7_const;
			
			A[n] <= h0_const;
			B[n] <= h1_const;
			C[n] <= h2_const;
			D[n] <= h3_const;
			E[n] <= h4_const;
			F[n] <= h5_const;
			G[n] <= h6_const;
			H[n] <= h7_const;
		 end
			
			cur_addr <= message_addr;
			offset <= 0;
			i <= 0;
			cur_we <= 1'b0;
			nonce_value <= 32'b0;
			state <= READ;
       end
    end
	
	 READ: begin
	   // READ all 20 input message words from memory same logic as in simplified_sha256 FSM
	   // end of this read message[0] to message[19] will have all 20 inpute message words
	   if (offset <= 20) begin
			if (offset != 0) begin
				message[offset-1] <= mem_read_data;
			end
			offset <= offset + 1;
			state <= READ;
		end else begin
			offset <= 0;
			state <= PHASE1_BLOCK; 
		end
	 end
	
	 PHASE1_BLOCK: begin
	    // Fill w[0] to w[15] with message[0] to message[15]
		for (int n = 0; n < 16; n++) w[0][n] <= message[n];
		
			  A[0] <= h0_const;
			  B[0] <= h1_const;
			  C[0] <= h2_const;
			  D[0] <= h3_const;
			  E[0] <= h4_const;
			  F[0] <= h5_const;
			  G[0] <= h6_const;
			  H[0] <= h7_const;
		
		i <= 0;
		state <= PHASE1_COMPUTE;
	 end

    PHASE1_COMPUTE: begin
       if (i <= 64) begin
		if(i<16) begin
			{A[0],B[0],C[0],D[0],E[0],F[0],G[0],H[0]} <= sha256_op(A[0],B[0],C[0],D[0],E[0],F[0],G[0],H[0],w[0][i],i);
         	end
         else begin
            for (int n = 0; n < 15; n++) w[0][n] <= w[0][n+1];
		w[0][15] <= wtnew(0, 16); // Perform word expansion 
		if (i != 16) begin
			{A[0],B[0],C[0],D[0],E[0],F[0],G[0],H[0]} <= sha256_op(A[0],B[0],C[0],D[0],E[0],F[0],G[0],H[0],w[0][15],i-1);
		end
	end
	  
        i <= i + 1;
	state <= PHASE1_COMPUTE;
       end
       else begin
		   
			 h0[0] <= h0[0] + A[0];
			 h1[0] <= h1[0] + B[0];
			 h2[0] <= h2[0] + C[0];
			 h3[0] <= h3[0] + D[0];
			 h4[0] <= h4[0] + E[0];
			 h5[0] <= h5[0] + F[0];
			 h6[0] <= h6[0] + G[0];
			 h7[0] <= h7[0] + H[0];
			
			 // Store phase1 output hash for later use at end of in PHASE3_COMPUTE before PHASE2_COMPUTE starts again for next nonce iteration
			 h0_out_phase1 <= h0[0] + A[0];
			 h1_out_phase1 <= h1[0] + B[0];
			 h2_out_phase1 <= h2[0] + C[0];
			 h3_out_phase1 <= h3[0] + D[0];
			 h4_out_phase1 <= h4[0] + E[0];
			 h5_out_phase1 <= h5[0] + F[0];
			 h6_out_phase1 <= h6[0] + G[0];
			 h7_out_phase1 <= h7[0] + H[0];
			
			 
			 state <= PHASE2_BLOCK;
		 end
    end
		
	 PHASE2_BLOCK: begin
	    // Fill in w[0] tp w[16] with message words, nonce and padding bits, message, size
		for (int m = 0; m < NUM_OF_NONCES; m++) begin 
			for (int n = 0; n < 3; n++) w[m][n] <= message[16 + n];
			w[m][3] <= m;
			w[m][4] <= 32'h80000000;
		 	for (int n = 5; n < 15; n++) w[m][n] <= 32'h00000000;
			w[m][15] <= 32'd640;
		end

       // Initialize a through h using h0 to h7 which was generated from PHASE1_COMPUTE
		for(int n=0; n<NUM_OF_NONCES; n++) begin
			h0[n] <= h0_out_phase1;
			h1[n] <= h1_out_phase1;
			h2[n] <= h2_out_phase1;
			h3[n] <= h3_out_phase1;
			h4[n] <= h4_out_phase1;
			h5[n] <= h5_out_phase1;
			h6[n] <= h6_out_phase1;
			h7[n] <= h7_out_phase1;
		 
			A[n] <= h0_out_phase1;
			B[n] <= h1_out_phase1;
			C[n] <= h2_out_phase1;
			D[n] <= h3_out_phase1;
			E[n] <= h4_out_phase1;
			F[n] <= h5_out_phase1;
			G[n] <= h6_out_phase1;
			H[n] <= h7_out_phase1;
      		end		
		i <= 0;
		state <= PHASE2_COMPUTE;
	 end
	 
	 PHASE2_COMPUTE: begin
	    // similar code as PHASE1_COMPUTE
       if (i <= 64) begin
		if(i<16) begin 
            		for (int n = 0; n < NUM_OF_NONCES; n++) begin
				{A[n],B[n],C[n],D[n],E[n],F[n],G[n],H[n]} <= sha256_op(A[n],B[n],C[n],D[n],E[n],F[n],G[n],H[n],w[n][i],i);
			end
         	end
         	else begin
			for (int m = 0; m < NUM_OF_NONCES; m++) begin
             		for (int n = 0; n < 15; n++) w[m][n] <= w[m][n+1];
			w[m][15] <= wtnew(m, 16); // Perform word expansion 
			if (i != 16) begin
				{A[m],B[m],C[m],D[m],E[m],F[m],G[m],H[m]} <= sha256_op(A[m],B[m],C[m],D[m],E[m],F[m],G[m],H[m],w[m][15],i-1);
			end
		end
        end
			
        i <= i + 1;
	state <= PHASE2_COMPUTE;
       end
       else begin
		for(int n=0; n<NUM_OF_NONCES; n++) begin
			h0[n] <= h0[n] + A[n];
			h1[n] <= h1[n] + B[n];
			h2[n] <= h2[n] + C[n];
			h3[n] <= h3[n] + D[n];
			h4[n] <= h4[n] + E[n];
			h5[n] <= h5[n] + F[n];
			h6[n] <= h6[n] + G[n];
			h7[n] <= h7[n] + H[n];
		end
			state <= PHASE3_BLOCK;
		end
       end

	PHASE3_BLOCK: begin
	// Fill in w[m][0] <= h0[m] to w[m][7] <= h7[m]
	for (int m = 0; m < NUM_OF_NONCES; m++) begin 
		w[m][0] <= h0[m];
		w[m][1] <= h1[m];
		w[m][2] <= h2[m];
		w[m][3] <= h3[m];
		w[m][4] <= h4[m];
		w[m][5] <= h5[m];
		w[m][6] <= h6[m];
		w[m][7] <= h7[m];
		w[m][8] <= 32'h80000000;
		for (int n = 9; n < 15; n++) w[m][n] <= 32'h00000000;
		w[m][15] <= 32'd256;
		
		// Initiatlize A through H with initial hash constants h0_const to h7_const
		A[m] <= h0_const;
		B[m] <= h1_const;
		C[m] <= h2_const;
		D[m] <= h3_const;
		E[m] <= h4_const;
		F[m] <= h5_const;
		G[m] <= h6_const;
		H[m] <= h7_const;
	end
	i <= 0;
	state <= PHASE3_COMPUTE;
	end
	 
	PHASE3_COMPUTE: begin
		if (i <= 64) begin
			if(i<16) begin 
            			for (int n = 0; n < NUM_OF_NONCES; n++) begin
					{A[n],B[n],C[n],D[n],E[n],F[n],G[n],H[n]} <= sha256_op(A[n],B[n],C[n],D[n],E[n],F[n],G[n],H[n],w[n][i],i);
				end
         		end
         		else begin
				for (int m = 0; m < NUM_OF_NONCES; m++) begin
             			for (int n = 0; n < 15; n++) w[m][n] <= w[m][n+1];
				w[m][15] <= wtnew(m, 16); // Perform word expansion 
				if (i != 16) begin
					{A[m],B[m],C[m],D[m],E[m],F[m],G[m],H[m]} <= sha256_op(A[m],B[m],C[m],D[m],E[m],F[m],G[m],H[m],w[m][15],i-1);
				end
			end
         	end
			
         	i <= i + 1;
	      	state <= PHASE3_COMPUTE;
	end
	else begin
		for(int n=0; n<NUM_OF_NONCES; n++) begin
			h0_out[n] <= h0_const + A[n];
			h1_out[n] <= h1_const + B[n];
			h2_out[n] <= h2_const + C[n];
			h3_out[n] <= h3_const + D[n];
			h4_out[n] <= h4_const + E[n];
			h5_out[n] <= h5_const + F[n];
			h6_out[n] <= h6_const + G[n];
			h7_out[n] <= h7_const + H[n];
			 
			// Transition state to PHASE2_BLOCK STATE
			state <= PHASE2_BLOCK;
			end
			// Transition state to WRITE STATE
			i <= 0;
			state <= WRITE;
		end
	end
 
				
	WRITE: begin
	   if (i <= 15) begin 
		// Write h0_out[0], h0_out[1], h0_out[2] to h0_out[15] to testbench memory
		i <= i + 1;
		offset <= i;
		cur_we <= 1'b1;
		cur_addr <= output_addr;
		cur_write_data <= (i == 0) ? h0_out[0]:
		(i == 1) ? h0_out[1]:
		(i == 2) ? h0_out[2]:
		(i == 3) ? h0_out[3]:
		(i == 4) ? h0_out[4]:
		(i == 5) ? h0_out[5]:
		(i == 6) ? h0_out[6]:
		(i == 7) ? h0_out[7]:
		(i == 8) ? h0_out[8]:
		(i == 9) ? h0_out[9]:
		(i == 10) ? h0_out[10]:
		(i == 11) ? h0_out[11]:
		(i == 12) ? h0_out[12]:
		(i == 13) ? h0_out[13]:
		(i == 14) ? h0_out[14]: h0_out[15];
			
		state <= WRITE;
	   end else begin
		state <= IDLE;
	   end
	end
  endcase

end

assign done = (state == IDLE);

endmodule
