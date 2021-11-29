<?php
    require 'db_connect.php';

    if(isset($_POST['register'])){
        if(registrasi($_POST) > 0){
                error('User berhasil ditambahkan');
                header("Location: login.php");
        }
    }
  
?>

<!DOCTYPE html>

<html lang="en">
  <head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Registrasi</title>

  <!-- Google Font: Source Sans Pro -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&amp;display=fallback">
  <!-- Font Awesome -->
  <link rel="stylesheet" href="../assets/css/all.min.css">
  <!-- icheck bootstrap -->
  <link rel="stylesheet" href="../assets/css/icheck-bootstrap.min.css">
  <!-- Theme style -->
  <link rel="stylesheet" href="../assets/css/adminlte.min.css">
  <link rel="stylesheet" href="../assets/css/fontawesome.min.css">
</head>

<body class="login-page" style="min-height: 466px;">
  <div class="login-box">
    <!-- /.login-logo -->
    <div class="card card-outline card-primary">
      <div class="card-header text-center">
        <a class="h1"><b>Register</b> Page</a>
      </div>
      <div class="card-body">
        <p class="login-box-msg">Daftarkan dirimu disini</p>

        <form class="regisForm" action="" method="post">
         <div class="input-group mb-3">
            <input type="text" class="form-control" placeholder="Nama Lengkap" name="nama" id="nama" required>
            <div class="input-group-append">
              <div class="input-group-text">
                <span class="fas fa-user-alt"></span>
              </div>
            </div>
          </div>
          <div class="input-group mb-3">
            <input type="email" class="form-control" placeholder="Email" name="email" id="email" required>
            <div class="input-group-append">
              <div class="input-group-text">
                <span class="fas fa-envelope"></span>
              </div>
            </div>
          </div>
          <div class="input-group mb-3">
            <input type="password" class="form-control" placeholder="Password" name="password" id="password" required>
            <div class="input-group-append">
              <div class="input-group-text">
                <span class="fas fa-lock"></span>
              </div>
            </div>
          </div>
          <div class="input-group mb-3">
            <input type="password" class="form-control" placeholder="Konfirmasi Password" name="password2" id="password2" required>
            <div class="input-group-append">
              <div class="input-group-text">
                <span class="fas fa-lock"></span>
              </div>
            </div>
          </div>
          <div class="row">
            <div class="col-4">
              <button type="submit" class="btn btn-primary btn-block" name="register">Register</button>
            </div>
            <a href="login.php" style="margin-top: 10px; margin-left: 20px">Already have an account? Log in</a>
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

