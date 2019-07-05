library IEEE;
use IEEE.STD_LOGIC_1164.all;
use ieee.numeric_std.all;
    entity shim_habr is
        Port ( clk : in  STD_LOGIC;
               BTN0 : in  STD_LOGIC;
               BTN1 : in  STD_LOGIC;
					BTN2 : in  STD_LOGIC;
               BTN3 : in  STD_LOGIC;
					an0 : out STD_LOGIC;
					an1 : out STD_LOGIC;
					an2 : out STD_LOGIC;
					an3 : out STD_LOGIC;
					CA : out STD_LOGIC;
					CB : out STD_LOGIC;
					CC : out STD_LOGIC;
					CD : out STD_LOGIC;
					CE : out STD_LOGIC;
					CF : out STD_LOGIC;
					CG : out STD_LOGIC;
					DP : out STD_LOGIC;
					LD0: out STD_LOGIC
				);
    end shim_habr;
    architecture Behavioral of shim_habr is

    constant clk_freq  : integer := 50_000_000;
    constant shim_freq : integer := 5;
    constant max_count : integer := clk_freq / shim_freq;

    signal count: integer range 0 to max_count := 0;
	 signal countf: integer range 0 to clk_freq := 0;
	 signal accumulator: unsigned(31 downto 0) := "00000000000000000000000000000000";
	 signal state : integer range 0 to 32 :=0;
	 signal view1 : std_logic_vector(7 downto 0) := "11111111";
	 signal view2 : std_logic_vector(7 downto 0) := "11111111";
	 signal view3 : std_logic_vector(7 downto 0) := "11111111";
	 signal view4 : std_logic_vector(7 downto 0) := "11111111";
    begin
	 printer: process (clk)
	 begin
		if rising_edge(clk) then
			if count < max_count/4 then
				an0 <= '1';	an1 <= '1';	an2 <= '1';	an3 <= '0';
				CA <= view1(7);CB <= view1(6);CC <= view1(5);CD <= view1(4);CE <= view1(3);CF <= view1(2);CG <= view1(1);
				DP <= view1(0);
			elsif count < max_count/2 then
				an0 <= '1';	an1 <= '1';	an2 <= '0';	an3 <= '1';
				CA <= view2(7);CB <= view2(6);CC <= view2(5);CD <= view2(4);CE <= view2(3);CF <= view2(2);CG <= view2(1);
				DP <= view2(0);
			elsif count < 3*max_count/4 then
				an0 <= '1';	an1 <= '0';	an2 <= '1';	an3 <= '1';
				CA <= view3(7);CB <= view3(6);CC <= view3(5);CD <= view3(4);CE <= view3(3);CF <= view3(2);CG <= view3(1);
				DP <= view3(0);
			elsif count < max_count then
				an0 <= '0';	an1 <= '1';	an2 <= '1';	an3 <= '1';
				CA <= view4(7);CB <= view4(6);CC <= view4(5);CD <= view4(4);CE <= view4(3);CF <= view4(2);CG <= view4(1);
				DP <= view4(0);
			end if;
		end if;
	 end process;

    clk1: process(clk)
    begin
      if rising_edge(clk) then
        if count = max_count then
				count <= 0;
        else
          count <= count + 1;
        end if;
      end if;
    end process;
view1 <= std_logic_vector(accumulator(31 downto 24));
view2 <= std_logic_vector(accumulator(23 downto 16));
view3 <= std_logic_vector(accumulator(15 downto 8));
view4 <= std_logic_vector(accumulator(7 downto 0));
    btns: process(clk,BTN0,BTN1,BTN2,BTN3)
	 variable a,b,c,d,e,f : unsigned(31 downto 0);
	 begin
		if rising_edge(clk) then
        if state = 0 then
		   countf <= 0;
			LD0 <= '0';
			if BTN0 = '1' then
				accumulator <= to_unsigned(646947 * 1,32);state <= 1;
			elsif BTN1 = '1' then
				accumulator <= to_unsigned(646947 * 2,32);state <= 1;
			elsif BTN2 = '1' then
				accumulator <= to_unsigned(646947 * 3,32);state <= 1;
			elsif BTN3 = '1' then
				accumulator <= to_unsigned(646947 * 4,32);state <= 1;
			end if;
		  elsif state = 1 then
		   countf <= countf + 1;LD0 <= '1';
			if countf = clk_freq then
				if BTN0 = '0' and BTN1 = '0' and BTN2 = '0' and BTN3 = '0' then
					state <= 2;
				end if;
			end if;
		  elsif state = 2 then
		   countf <= 0;LD0 <= '0';
		   a := (accumulator + to_unsigned(787242,32));
			if BTN0 = '1' then
				accumulator <= a;state <= 3;
			elsif BTN1 = '1' then
				accumulator <= a sll 1;state <= 3;
			elsif BTN2 = '1' then
				accumulator <= (a sll 1) + a;state <= 3;
			elsif BTN3 = '1' then
				accumulator <= a sll 2;state <= 3;
			end if;
		  elsif state = 3 then
		   countf <= countf + 1;LD0 <= '1';
			if countf = clk_freq then
				if BTN0 = '0' and BTN1 = '0' and BTN2 = '0' and BTN3 = '0' then
					state <= 4;
				end if;
			end if;
		  elsif state = 4 then
		   countf <= 0;LD0 <= '0';
			b := (accumulator + to_unsigned(385656,32));
			if BTN0 = '1' then
				accumulator <= b;state <= 5;
			elsif BTN1 = '1' then
				accumulator <= b sll 1;state <= 5;
			elsif BTN2 = '1' then
				accumulator <= (b sll 1) + b;state <= 5;
			elsif BTN3 = '1' then
				accumulator <= b sll 2;state <= 5;
			end if;
		  elsif state = 5 then
		   countf <= countf + 1;LD0 <= '1';
			if countf = clk_freq then
				if BTN0 = '0' and BTN1 = '0' and BTN2 = '0' and BTN3 = '0' then
					state <= 6;
				end if;
			end if;
		  elsif state = 6 then
		   countf <= 0;LD0 <= '0';
		   c := (accumulator + to_unsigned(151583,32));
		  	if BTN0 = '1' then
				accumulator <= c;state <= 7;
			elsif BTN1 = '1' then
				accumulator <= c sll 1;state <= 7;
			elsif BTN2 = '1' then
				accumulator <= (c sll 1) + c;state <= 7;
			elsif BTN3 = '1' then
				accumulator <= c sll 2;state <= 7;
			end if;
		 elsif state = 7 then
		   countf <= countf + 1;LD0 <= '1';
			if countf = clk_freq then
				if BTN0 = '0' and BTN1 = '0' and BTN2 = '0' and BTN3 = '0' then
					state <= 8;
				end if;
			end if;
		  elsif state = 8 then
		   countf <= 0;LD0 <= '0';
		   d := (accumulator + to_unsigned(101591,32));
		  	if BTN0 = '1' then
				accumulator <= d;state <= 9;
			elsif BTN1 = '1' then
				accumulator <= d sll 1;state <= 9;
			elsif BTN2 = '1' then
				accumulator <= (d sll 1) + d;state <= 9;
			elsif BTN3 = '1' then
				accumulator <= d sll 2;state <= 9;
			end if;
		  elsif state = 9 then
		   countf <= countf + 1;LD0 <= '1';
			if countf = clk_freq then
				if BTN0 = '0' and BTN1 = '0' and BTN2 = '0' and BTN3 = '0' then
					state <= 10;
				end if;
			end if;
		  elsif state = 10 then
		   countf <= 0;LD0 <= '0';
		   e := (accumulator + to_unsigned(118067,32));
		  	if BTN0='1' then
				accumulator <= e;state <= 11;
			elsif BTN1='1' then
				accumulator <= e sll 1;state <= 11;
			elsif BTN2='1' then
				accumulator <= (e sll 1) + e;state <= 11;
			elsif BTN3='1' then
				accumulator <= e sll 2;state <= 11;
			end if;
		  elsif state = 11 then
		   countf <= countf + 1;LD0 <= '1';
			if countf = clk_freq then
				if BTN0 = '0' and BTN1 = '0' and BTN2 = '0' and BTN3 = '0' then
					state <= 12;
				end if;
			end if;
		  elsif state = 12 then
		   countf <= 0;LD0 <= '0';
		   f := (accumulator + to_unsigned(701881,32));
		  	if BTN0='1' then
				accumulator <= f;	state <= 13;
			elsif BTN1='1' then
				accumulator <= f sll 1;state <= 13;
			elsif BTN2='1' then
				accumulator <= (f sll 1) + f;state <= 13;
			elsif BTN3='1' then
				accumulator <= f sll 2;	state <= 13;
			end if;
		  elsif state = 13 then
		   countf <= countf + 1;LD0 <= '1';
			if countf = clk_freq then
				if BTN0 = '0' and BTN1 = '0' and BTN2 = '0' and BTN3 = '0' then
					state <= 14;
				end if;
			end if;
		  elsif state = 14 then
				state <= 0;LD0 <= '0';
		  end if;
      end if;
	 end process;
    end Behavioral;
