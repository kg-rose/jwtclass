jwt�࣬��������jwt�ͽ���jwt

�÷�
   $jwt = new Jwt();
   $jwttoken = new JwtToken($jwt);
   //����
   $token = $jwttoken->setToken();
   //����
   $check = json_decode($jwttoken->checkToken($token));
