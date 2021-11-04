<?php
    $email = $_POST["email"];
    $pass = $_POST["password"];

    if($email == "hnffzh@gmail.com" && $pass == "12345"){
        header("Location: ../Dashboard/tabel.html");
        exit();
    }
    else{
        echo "Password atau Email anda Salah";
    }
?>