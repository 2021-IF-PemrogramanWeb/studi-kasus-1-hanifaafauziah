<?php
  session_start();
  require 'db_connect.php';
  if(!isset($_SESSION["login"])){
    header("location: login.php");
    exit;
  }
  $no = mysqli_query($conn,"SELECT id FROM trend");
  $value = mysqli_query($conn,"SELECT value FROM trend");
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Grafik</title>

  <!-- Google Font: Source Sans Pro -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
  <!-- Font Awesome -->
  <link rel="stylesheet" href="../assets/css/all.min.css">
  <!-- Theme style -->
  <link rel="stylesheet" href="../assets/css/adminlte.min.css">
  <link rel="stylesheet" href="../assets/css/fontawesome.min.css">
  <script src="assets/js/Chart.js" type="text/javascript"></script>
</head>
<body class="hold-transition sidebar-mini">
<div class="wrapper">
  <!-- Navbar -->
  <nav class="main-header navbar navbar-expand navbar-white navbar-light">
    <!-- Left navbar links -->
    <ul class="navbar-nav">
      <li class="nav-item">
        <a href="#" class="nav-link" data-widget="pushmenu" href="#" role="button"><i class="fas fa-bars"></i></a>
      </li>
      <li class="nav-item d-none d-sm-inline-block">
        <a href="tabel.php" class="nav-link">Home</a>
      </li>
      <li class="nav-item d-none d-sm-inline-block">
        <a href="logout.php" class="nav-link">Logout</a>
      </li>
    </ul>
  </nav>
  <!-- /.navbar -->

  <!-- Main Sidebar Container -->
  <aside class="main-sidebar sidebar-dark-primary elevation-4">

    <!-- Sidebar -->
    <div class="sidebar">
      <!-- Sidebar user panel (optional) -->
      <div class="user-panel mt-3 pb-3 mb-3 d-flex">
        <div class="image mt-1">
          <img src="assets/eagle.jpg" class="img-circle elevation-2" alt="Image">
        </div>
        <div class="info">
          <!-- <i class="fas fa-tachometer-alt"></i> -->
          <a href="#" class="d-block">Welcome to Dashboard!</a>
        </div>
      </div>

      <!-- Sidebar Menu -->
      <nav class="mt-2">
        <ul class="nav nav-pills nav-sidebar flex-column" data-widget="treeview" role="menu" data-accordion="false">
          <!-- Add icons to the links using the .nav-icon class
               with font-awesome or any other icon font library -->
          <li class="nav-item">
            <a href="tabel.php" class="nav-link">
              <i class="nav-icon fas fa-columns"></i>
              <p>
                Tabel
              </p>
            </a>
          </li>
          <li class="nav-item">
            <a href="grafik.php" class="nav-link m-0">
              <i class="nav-icon fas fa-chart-bar"></i>
              <p>
                Grafik
              </p>
            </a>
          </li>
          <li class="nav-item">
            <a href="sqldata.php" class="nav-link m-0">
              <i class="nav-icon fas fa-database"></i>
              <p>
                SQL Data
              </p>
            </a>
          </li>
        </ul>
      </nav>
      <!-- /.sidebar-menu -->
    </div>
    <!-- /.sidebar -->
  </aside>

  <!-- Content Wrapper. Contains page content -->
  <div class="content-wrapper">
    <!-- Content Header (Page header) -->
    <section class="content-header">
      <div class="container-fluid">
        <div class="row mb-2">
          <div class="col-sm-6">
            <h1>
              <i class="far fa-chart-bar"></i>
              Grafik
            </h1>
          </div>
          <div class="col-sm-6">
            <ol class="breadcrumb float-sm-right">
              <li class="breadcrumb-item"><a href="tabel.php">Home</a></li>
              <li class="breadcrumb-item active">Grafik</li>
            </ol>
          </div>
        </div>
      </div><!-- /.container-fluid -->
    </section>

    <!-- Main content -->
    <section class="content">
      <div class="card card-primary card-outline">
        <div class="card-header">
          <h3 class="card-title float-right" >
            Tanggal Hari Ini: <span id="date"></span>
          </h3>
        </div>
        <div class="card-body">
          <h3 class="text-center">Trend of Reason</h3>
          <!-- <div id="bar-chart" style="height: 300px;"></div> -->
          <center>
            <canvas id="trend"></canvas>
          </center>

          <script>
            var ctx = document.getElementById("trend").getContext('2d');
            var myChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: [<?php while($row = mysqli_fetch_array($no)) {echo '"'.$row['id']. '",';}?>],
                    datasets: 
                    [
                        {
                            label: 'Trend of reason',
                            data: [<?php while($row = mysqli_fetch_array($value)) {echo '"'.$row['value']. '",';}?>, 10],
                            backgroundColor: ['#17BEBB', '#17BEBB', '#17BEBB', '#17BEBB' ,'#17BEBB',
                                              '#17BEBB', '#17BEBB', '#17BEBB', '#17BEBB' ,'#17BEBB',
                                              '#17BEBB', '#17BEBB', '#17BEBB', '#17BEBB' ,'#17BEBB', '#17BEBB'],
                            borderWidth: 1
                        }
                    ]
                },
            options: {
                scales: {
                    yAxes: [{
                        ticks: {
                            beginAtZero:true
                        }
                    }]
                    }
                }
            });
          </script>

        </div>
        <!-- /.card-body-->
      </div>
    </section>
    <!-- /.content -->
  </div>
  <!-- /.content-wrapper -->

  <footer class="main-footer">
    <div class="float-right d-none d-sm-block">
      <b>Version</b> 1.0
    </div>
    <strong>Copyright &copy; 2021 Hanifa Fauziah.</strong> All rights reserved.
  </footer>

  <!-- Control Sidebar -->
  <aside class="control-sidebar control-sidebar-dark">
    <!-- Control sidebar content goes here -->
  </aside>
  <!-- /.control-sidebar -->
</div>
<!-- ./wrapper -->

<!-- jQuery -->
<script src="../assets/jquery/jquery.min.js"></script>
<!-- Bootstrap 4 -->
<script src="../assets/js/bootstrap.bundle.min.js"></script>
<!-- AdminLTE App -->
<script src="../assets/js/adminlte.min.js"></script>
<!-- FLOT CHARTS -->
<script src="../assets/flot/jquery.flot.js"></script>
<!-- FLOT RESIZE PLUGIN - allows the chart to redraw when the window is resized -->
<script src="../assets/flot/plugins/jquery.flot.resize.js"></script>
<!-- Page specific script -->
<script>

  n =  new Date();
  y = n.getFullYear();
  m = n.getMonth() + 1;
  d = n.getDate();
  document.getElementById("date").innerHTML = d + "/" + m + "/" + y;

</script>
</body>
</html>
