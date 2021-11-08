<?php

  session_start();
  require 'db_connect.php';

  if(isset($_COOKIE['num']) && isset($_COOKIE['key'])){
    $num = $_COOKIE['num'];
    $key = $_COOKIE['key'];

    $result = mysqli_query($conn, "SELECT email FROM users WHERE id = '$num' ");
    $row = mysqli_fetch_assoc($result);

    if($key === hash('sha256', $row['email'])){
        $_SESSION['login'] = true;
    }

  }

  if(isset($_SESSION["login"])){
    header("location: tabel.php");
    exit;
  }


  
  if(isset($_POST["login"])){

		$email = $_POST["email"];
    $password = $_POST["password"];

    $result = mysqli_query($conn, "SELECT * FROM users WHERE email = '$email' ");

    if(mysqli_num_rows($result)===1){

      $row = mysqli_fetch_assoc($result);
      if(password_verify($password, $row["password"])){

        $_SESSION["login"] = true;

        if(isset($_POST['remember'])){
          setcookie('num', $row['id'], time()+60);
          setcookie('key', hash('sha256', $row['email']), time()+60);
        }

        header("location: tabel.php");
        exit;
      }

    }

    if(empty($email) && empty($password)){
      error("Silahkan masukkan email dan password anda.");
      $error=1;
    }

    else if(empty($email)){
      error("Silahkan masukkan email anda.");
      $error=1;
    }

    else if(empty($password)){
      error("Silahkan masukkan password anda.");
      $error=1;
    }

    else{
      error("Email / Password tidak sesuai");
    }

  }
  
?>

<!DOCTYPE html>
<html lang="en">
  <head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login</title>

  <!-- Google Font: Source Sans Pro -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&amp;display=fallback">
  <!-- Font Awesome -->
  <link rel="stylesheet" href="../assets/css/all.min.css">
  <!-- icheck bootstrap -->
  <link rel="stylesheet" href="../assets/css/icheck-bootstrap.min.css">
  <!-- Theme style -->
  <link rel="stylesheet" href="../assets/css/adminlte.min.css">
  <link rel="stylesheet" href="../assets/css/fontawesome.min.css">
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css">
</head>

<body class="login-page" style="min-height: 466px;">
  <div class="login-box">
    <!-- /.login-logo -->
    <div class="card card-outline card-primary">
      <div class="card-header text-center">
        <a class="h1"><b>Login</b> Page</a>
      </div>
      <div class="card-body">
        <p class="login-box-msg">Log in to start your session</p>
  
        <form name="loginForm" method="post" action="">
          <div class="input-group mb-3">
            <input type="email" class="form-control" placeholder="Email" name="email" id="email">
            <div class="input-group-append">
              <div class="input-group-text">
                <span class="fas fa-envelope"></span>
              </div>
            </div>
          </div>
          <div class="input-group mb-3">
            <input type="password" class="form-control" placeholder="Password" name="password" id="password"> 
            <div class="input-group-append">
              <div class="input-group-text">
                <span class="fas fa-lock"></span>
              </div>
            </div>
          </div>
          <div class="input-group mb-3 form-check">
            <input class="form-check-input" type="checkbox" name="remember" id="remember">
            <label class="form-check-label">Remember me</label>
          </div>
          <!-- </div> -->
          <div class="row">
            <div class="col-4">
              <button type="submit" name="login" class="btn btn-primary btn-block">Log In</button>
            </div>
            <a href="register.php" style="margin-top: 10px; padding-left:10px;">Don't have an account yet? Register here</a>

          </div>
        </form>
      </div>
      <!-- /.card-body -->
    </div>
    <!-- /.card -->
  </div>
  <!-- /.login-box -->
  </body>

</html>
