<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tabel Employee</title>

  <!-- Google Font: Source Sans Pro -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
  <!-- Font Awesome -->
  <link rel="stylesheet" href="../assets/css/all.min.css">
  <!-- Theme style -->
  <link rel="stylesheet" href="../assets/css/adminlte.min.css">
  <link rel="stylesheet" href="../assets/css/fontawesome.min.css">
</head>
<body>
<div class="wrapper">
    <!-- Navbar -->
    <nav class="main-header navbar navbar-expand navbar-white navbar-light">
      <!-- Left navbar links -->
      <ul class="navbar-nav">
        <li class="nav-item">
          <a href="#" class="nav-link" data-widget="pushmenu" href="#" role="button"><i class="fas fa-bars"></i></a>
        </li>
        <li class="nav-item d-none d-sm-inline-block">
          <a href="../../index3.html" class="nav-link">Home</a>
        </li>
        <li class="nav-item d-none d-sm-inline-block">
          <a href="#" class="nav-link">Contact</a>
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
                <a href="../Dashboard/tabel.html" class="nav-link">
                  <i class="nav-icon fas fa-columns"></i>
                  <p>
                    Tabel
                  </p>
                </a>
              </li>
              <li class="nav-item">
                <a href="../Dashboard/grafik.html" class="nav-link m-0">
                  <i class="nav-icon fas fa-chart-bar"></i>
                  <p>
                    Grafik
                  </p>
                </a>
              </li>
              <li class="nav-item">
                <a href="../Dashboard/sqldata.php" class="nav-link m-0">
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
    <div class="content-wrapper">
      <!-- Content Header (Page header) -->
      <section class="content-header">
        <div class="container-fluid">
          <div class="row mb-2">
            <div class="col-sm-6">
              <h1>
                <i class="nav-icon fas fa-database"></i>
                SQL Data</h1>
            </div>
            <div class="col-sm-6">
              <ol class="breadcrumb float-sm-right">
                <li class="breadcrumb-item"><a href="#">Home</a></li>
                <li class="breadcrumb-item active">SQL Data</li>
              </ol>
            </div>
          </div>
        </div><!-- /.container-fluid -->
      </section>

      <!-- Main content -->
      <section class="content">
        <div class="container-fluid"></div>
          <div class="row">
            <div class="col-12">
              <div class="card">
                <div class="card-header">
                  <h3 class="card-title float-right" >
                    Tanggal Hari Ini: <span id="date"></span>
                  </h3>
                </div>
                <!-- /.card-header -->
                <div class="card-body">
                <h3 class="text-center">Database Employee</h3>
                  <table id="tabelkaryawan" class="table table-bordered table-striped">
                      <thead>
                      <tr>
                        <th>Employee ID</th>
                        <th>Nama</th>
                        <th>Umur</th>
                      </tr>
                      </thead>
                      <tbody>
                      <?php
                          $conn = mysqli_connect("localhost", "root", "", "datadummy");

                          if ($conn->connect_error) {
                            die("Connection failed: " . $conn->connect_error);
                          }
                          
                          $sql = "SELECT E_ID, Nama, Umur FROM employee";
                          $result = $conn->query($sql);

                          if($result -> num_rows > 0){
                            while($row = $result -> fetch_assoc()){
                              echo "<tr><td>".$row["E_ID"]."</td><td>".
                                              $row["Nama"]."</td><td>".
                                              $row["Umur"]."</td></tr>";
                            }
                            echo "</tbody></table>";
                          }
                          else{
                            echo "0 result";
                          }

                          $conn -> close();
                      ?>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
      <footer class="main-footer">
      <div class="float-right d-none d-sm-block">
        <b>Version</b> 1.0
      </div>
      <strong>Copyright &copy; 2021 Hanifa Fauziah.</strong> All rights reserved.
    </footer>
    </div>

    <!-- /.content-wrapper -->
    
</div>
</body>
</html>