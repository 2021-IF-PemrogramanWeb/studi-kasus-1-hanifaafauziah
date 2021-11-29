<?php

  session_start();
  require 'db_connect.php';

  if(isset($_COOKIE['num']) && isset($_COOKIE['key'])){
    $num = $_COOKIE['num'];
    $key = $_COOKIE['key'];

    $stmt = $conn->prepare("SELECT email FROM users WHERE id = ?");

		if (!$stmt) {
			die('Query Error : '.$mysqli->errno.
			' - '.$mysqli->error);
		}

		$stmt->bind_param("s", $num);
		$stmt->execute();
		$result = $stmt->get_result();

    // $result = mysqli_query($conn, "SELECT email FROM users WHERE id = '$num' ");
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
    $email=(filter_var($email,  FILTER_SANITIZE_EMAIL));
    $password = $_POST["password"];
    $password=(filter_var($password,  FILTER_SANITIZE_STRING));

    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");

		if (!$stmt) {
			die('Query Error : '.$mysqli->errno.
			' - '.$mysqli->error);
		}

		$stmt->bind_param("s", $email);
		$stmt->execute();
		$result = $stmt->get_result();
    if(empty($email) && empty($password)){
      error("Silahkan masukkan email dan password anda.");
      $error=1;
    }
    else if(mysqli_num_rows($result)===1 && $password != null){

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
      else if(password_verify($password, $row["password"])==0){
        error("Email/Password yang anda masukkan tidak valid.");
      }

    }
    else{
      error("Email/Password yang anda masukkan tidak valid.");
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
