module bitcoin_hash_serial(input logic        clk, reset_n, start,
                    input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                    input logic [31:0] mem_read_data);

// Number of NONCES
parameter integer NUM_OF_NONCES=16;

//Local Variables
logic [31:0] w[16];
logic [31:0] message[20];
logic [31:0] a, b, c, d, e, f, g, h;
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
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

function logic [31:0] wtnew(logic [7:0] t);
	logic [31:0] s1, s0;
	s0 = rightrotate(w[t-15], 7) ^ rightrotate(w[t-15], 18) ^ (w[t-15] >> 3);
	s1 = rightrotate(w[t-2], 17) ^ rightrotate(w[t-2], 19) ^ (w[t-2] >> 10);
	wtnew = w[t-16] + s0 + w[t-7] + s1;
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


// Trying to Implement State Machine
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
	      h0 <= h0_const;
		   h1 <= h1_const;
			h2 <= h2_const;
			h3 <= h3_const;
			h4 <= h4_const;
			h5 <= h5_const;
			h6 <= h6_const;
			h7 <= h7_const;

			a <= h0_const;
			b <= h1_const;
			c <= h2_const;
			d <= h3_const;
			e <= h4_const;
			f <= h5_const;
			g <= h6_const;
			h <= h7_const;
			
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
		for (int n = 0; n < 16; n++) w[n] <= message[n];
		
		// Initial hash constants
		a <= h0_const;
		b <= h1_const;
		c <= h2_const;
		d <= h3_const;
		e <= h4_const;
		f <= h5_const;
		g <= h6_const;
		h <= h7_const;
		
		i <= 0;
		state <= PHASE1_COMPUTE;
	 end

    PHASE1_COMPUTE: begin
       if (i <= 64) begin
      
	      // Add similar code as in COMPUTE FSM state in simplified_sha256 FSM
			if(i<16) begin 
            {a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
         end
         else begin
            for (int n = 0; n < 15; n++) w[n] <= w[n+1];
				w[15] <= wtnew(16); // Perform word expansion 
				if (i != 16) {a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i-1);
         end
	  
         i <= i + 1;
	      state <= PHASE1_COMPUTE;
       end
       else begin
			 h0 <= h0 + a;
			 h1 <= h1 + b;
			 h2 <= h2 + c;
			 h3 <= h3 + d;
			 h4 <= h4 + e;
			 h5 <= h5 + f;
			 h6 <= h6 + g;
			 h7 <= h7 + h;
			 
			 // Store phase1 output hash for later use at end of in PHASE3_COMPUTE before PHASE2_COMPUTE starts again for next nonce iteration
			 h0_out_phase1 <= h0 + a;
			 h1_out_phase1 <= h1 + b;
			 h2_out_phase1 <= h2 + c;
			 h3_out_phase1 <= h3 + d;
			 h4_out_phase1 <= h4 + e;
			 h5_out_phase1 <= h5 + f;
			 h6_out_phase1 <= h6 + g;
			 h7_out_phase1 <= h7 + h;
			 
			 state <= PHASE2_BLOCK;
		 end
    end
		
	 PHASE2_BLOCK: begin
	    // Add code to Fill in w[0] tp w[16] with message words, nonce and padding bits, message, size
		//w[0] to w[2] using message[16] to message[18]
		//w[3] <= nonce_value;
		//w[4] <= 32'h80000000;
		//w[5] to w[14] to 0
		//w[15] = 32'd640;
		for (int n = 0; n < 3; n++) w[n] <= message[16 + n];
		w[3] <= nonce_value;
		w[4] <= 32'h80000000;
		for (int n = 5; n < 15; n++) w[n] <= 32'h00000000;
		w[15] <= 32'd640;

      // Initialize a through h using h0 to h7 which was generated from PHASE1_COMPUTE
		a <= h0;
		b <= h1;
		c <= h2;
		d <= h3;
		e <= h4;
		f <= h5;
		g <= h6;
		h <= h7;
		
		i <= 0;
		state <= PHASE2_COMPUTE;
	 end
	 
	 PHASE2_COMPUTE: begin
	    // similar code as PHASE1_COMPUTE
       if (i <= 64) begin
			if(i<16) begin 
            {a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
         end
         else begin
            for (int n = 0; n < 15; n++) w[n] <= w[n+1];
				w[15] <= wtnew(16); // Perform word expansion 
				if (i != 16) {a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i-1);
         end
			
         i <= i + 1;
	      state <= PHASE2_COMPUTE;
       end
       else begin
	       // Add similar code from PHASE1_COMPUTE
			 h0 <= h0 + a;
			 h1 <= h1 + b;
			 h2 <= h2 + c;
			 h3 <= h3 + d;
			 h4 <= h4 + e;
			 h5 <= h5 + f;
			 h6 <= h6 + g;
			 h7 <= h7 + h;
			 
			 state <= PHASE3_BLOCK;
		 end
    end

	 PHASE3_BLOCK: begin
	   // Add code to fill in w[0] <= h0 to w[7] <=h7
		// Fill in w[8] = 32'h80000000;
		// w[9] to w[14] to 0
		// w[15] = 32'd256;
		w[0] <= h0;
		w[1] <= h1;
		w[2] <= h2;
		w[3] <= h3;
		w[4] <= h4;
		w[5] <= h5;
		w[6] <= h6;
		w[7] <= h7;
		w[8] <= 32'h80000000;
		for (int n = 9; n < 15; n++) w[n] <= 32'h00000000;
		w[15] <= 32'd256;
		
		// Add code to initiatlize a through h with initial hash constants h0_const to h7_const
		a <= h0_const;
		b <= h1_const;
		c <= h2_const;
		d <= h3_const;
		e <= h4_const;
		f <= h5_const;
		g <= h6_const;
		h <= h7_const;
		
		i <= 0;
		state <= PHASE3_COMPUTE;
	 end
	 
	 PHASE3_COMPUTE: begin
		if (i <= 64) begin
		  // Add similar code as in PHASE1_COMPUTE or PHASE2_COMPUTE
		  if(i < 16) begin 
            {a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
         end
         else begin
            for (int n = 0; n < 15; n++) w[n] <= w[n+1];
				w[15] <= wtnew(16); // Perform word expansion 
				if (i != 16) {a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i-1);
         end
			i <= i + 1;
        end
		  else begin
		    h0_out[nonce_value] <= h0_const + a;
			 h1_out[nonce_value] <= h1_const + b;
			 h2_out[nonce_value] <= h2_const + c;
			 h3_out[nonce_value] <= h3_const + d;
			 h4_out[nonce_value] <= h4_const + e;
			 h5_out[nonce_value] <= h5_const + f;
			 h6_out[nonce_value] <= h6_const + g;
			 h7_out[nonce_value] <= h7_const + h;
			 
			 if(nonce_value < 16) begin
			    nonce_value <= nonce_value + 1;
				
				// Add code to Restore phase1 hash output to h0 to h7 as a starting input hash value for PHASE2_BLOCK and PHASE2_COMPUTE for next nonce value iteration
			   h0 <= h0_out_phase1;
				h1 <= h1_out_phase1;
				h2 <= h2_out_phase1;
				h3 <= h3_out_phase1;
				h4 <= h4_out_phase1;
				h5 <= h5_out_phase1;
				h6 <= h6_out_phase1;
				h7 <= h7_out_phase1;
				
			   // Add code to Transition state to PHASE2_BLOCK STATE
			   state <= PHASE2_BLOCK;
			 end else begin
			   // Add code to Transition state to WRITE STATE
				i <= 0;
			   state <= WRITE;
			 end
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
	 