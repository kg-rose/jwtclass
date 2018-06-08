<?php

namespace app\core\helper;

class JwtToken implements \app\core\helper\Token
{
    private $adaptee;

    function __construct($adaptee)
    {
        $this->adaptee = $adaptee;
    }

    public function setToken()
    {
        // TODO: Implement checkToken() method.
      return  $this->adaptee->createToken();
    }

    public function checkToken($token)
    {
        // TODO: Implement checkToken() method.
      return  $this->adaptee->validateToken($token);
    }
}