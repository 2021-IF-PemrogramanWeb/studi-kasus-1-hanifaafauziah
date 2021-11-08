<?php
  session_start();
  if(!isset($_SESSION["login"])){
    header("location: login.php");
    exit;
  }
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tabel</title>

  <!-- Google Font: Source Sans Pro -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
  <!-- Font Awesome -->
  <link rel="stylesheet" href="../assets/css/all.min.css">
  <!-- Theme style -->
  <link rel="stylesheet" href="../assets/css/adminlte.min.css">
  <link rel="stylesheet" href="../assets/css/fontawesome.min.css">
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
        <!-- <a href="#" class="nav-link">Contact</a> -->
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
              <i class="nav-icon fas fa-columns"></i>
              Tabel</h1>
          </div>
          <div class="col-sm-6">
            <ol class="breadcrumb float-sm-right">
              <li class="breadcrumb-item"><a href="#">Home</a></li>
              <li class="breadcrumb-item active">Tabel</li>
            </ol>
          </div>
        </div>
      </div><!-- /.container-fluid -->
    </section>

    <!-- Main content -->
    <section class="content">
      <div class="container-fluid">
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
                <table id="datatable" class="table table-bordered table-striped">
                  <thead>
                  <tr>
                    <th>No</th>
                    <th>On</th>
                    <th>Off</th>
                    <th>Ack by</th>
                    <th>Reason</th>
                  </tr>
                  </thead>
                  <tbody>

                  <?php
                    $conn = mysqli_connect("localhost", "root", "", "datadummy");

                    if ($conn->connect_error) {
                      die("Connection failed: " . $conn->connect_error);
                    }
                          
                    $sql = "SELECT no, t_on, t_off, ack_by, reason FROM tables";
                    $result = $conn->query($sql);

                    if($result -> num_rows > 0){
                      while($row = $result -> fetch_assoc()){
                        echo "<tr><td>".$row["no"]."</td><td>".
                                        $row["t_on"]."</td><td>".
                                        $row["t_off"]."</td><td>".
                                        $row["ack_by"]."</td><td>".
                                        $row["reason"]."</td></tr>";
                      }
                      echo "</tbody></table>";
                    }
                    else{
                      echo "0 result";
                    }
                    $conn -> close();
                  ?>
              </div>
              <!-- /.card-body -->
            </div>
            <!-- /.card -->
          </div>
          <!-- /.col -->
         
          <div class="col-md-2">
            <button type="button" class="btn btn-block btn-primary" 
                onclick="exportTableToExcel('datatable', 'download')">
                Export to Excel
            </button>
          </div>
          <div class="col-md-2"> 
            <form action="logout.php" method="get">
              <button type="submit" class="btn btn-block btn-warning">Logout</button>
            </form>
          </div>
        </div>
        <!-- /.row -->


        <!-- /.content -->
      </div>
      <br>
      </div>
      <!-- /.container-fluid -->
    </section>
    <footer class="main-footer">
      <div class="float-right d-none d-sm-block">
        <b>Version</b> 1.0
      </div>
      <strong>Copyright &copy; 2021 Hanifa Fauziah.</strong> All rights reserved.
    </footer>


  <!-- /.content-wrapper -->


</div>
<!-- ./wrapper -->

<!-- jQuery -->
<script src="../assets/jquery/jquery.min.js"></script>
<!-- Bootstrap 4 -->
<script src="../assets/js/bootstrap.bundle.min.js"></script>
<!-- DataTables  & Plugins -->
<script src="../assets/jquery/jquery.dataTables.min.js"></script>
<script src="../assets/js/dataTables.bootstrap4.min.js"></script>
<script src="../assets/js/dataTables.responsive.min.js"></script>
<script src="../assets/js/responsive.bootstrap4.min.js"></script>
<script src="../assets/js/dataTables.buttons.min.js"></script>
<script src="../assets/js/buttons.bootstrap4.min.js"></script>
<script src="../assets/js/jszip.min.js"></script>
<script src="../assets/js//pdfmake.min.js"></script>
<script src="../assets/js/vfs_fonts.js"></script>
<script src="../assets/js/buttons.html5.min.js"></script>
<script src="../assets/js/buttons.print.min.js"></script>
<script src="../assets/js/buttons.colVis.min.js"></script>
<!-- AdminLTE App -->
<script src="../assets/js/adminlte.min.js"></script>

<!-- Page specific script -->
<script>
  n =  new Date();
  y = n.getFullYear();
  m = n.getMonth() + 1;
  d = n.getDate();
  document.getElementById("date").innerHTML = d + "/" + m + "/" + y;

  function exportTableToExcel(tableID, filename = ''){
    var downloadLink;
    var dataType = 'application/vnd.ms-excel';
    var tableSelect = document.getElementById(tableID);
    var tableHTML = tableSelect.outerHTML.replace(/ /g, '%20');
      
      // Specify file name
    filename = filename?filename+'.xls':'excel_data.xls';
      
      // Create download link element
    downloadLink = document.createElement("a");
      
    document.body.appendChild(downloadLink);
      
    if(navigator.msSaveOrOpenBlob){
      var blob = new Blob(['\ufeff', tableHTML], {
      type: dataType
      });
      navigator.msSaveOrOpenBlob( blob, filename);
    }
    else{
          // Create a link to the file
        downloadLink.href = 'data:' + dataType + ', ' + tableHTML;
      
          // Setting the file name
        downloadLink.download = filename;
          
          //triggering the function
        downloadLink.click();
    }
  }
  

</script>
</body>
</html>
