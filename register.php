

    <?php

    // Include config file

    require_once 'config.php';

     

    // Define variables and initialize with empty values

    $username = $password = $confirm_password = "";

    $username_err = $password_err = $confirm_password_err = "";

     

    // Processing form data when form is submitted

    if($_SERVER["REQUEST_METHOD"] == "POST"){

     

        // Validate username

        if(empty(trim($_POST["username"]))){

            $username_err = "Please enter a username.";

        } else{

            // Prepare a select statement

            $sql = "SELECT id FROM users WHERE username = ?";

            

            if($stmt = mysqli_prepare($link, $sql)){

                // Bind variables to the prepared statement as parameters

                mysqli_stmt_bind_param($stmt, "s", $param_username);

                

                // Set parameters

                $param_username = trim($_POST["username"]);

                

                // Attempt to execute the prepared statement

                if(mysqli_stmt_execute($stmt)){

                    /* store result */

                    mysqli_stmt_store_result($stmt);

                    

                    if(mysqli_stmt_num_rows($stmt) == 1){

                        $username_err = "This username is already taken.";

                    } else{

                        $username = trim($_POST["username"]);

                    }

                } else{

                    echo "Oops! Something went wrong. Please try again later.";

                }

            }

             

            // Close statement

            mysqli_stmt_close($stmt);

        }

        

        // Validate password

        if(empty(trim($_POST['password']))){

            $password_err = "Please enter a password.";     

        } elseif(strlen(trim($_POST['password'])) < 6){

            $password_err = "Password must have atleast 6 characters.";

        } else{

            $password = trim($_POST['password']);

        }

        

        // Validate confirm password

        if(empty(trim($_POST["confirm_password"]))){

            $confirm_password_err = 'Please confirm password.';     

        } else{

            $confirm_password = trim($_POST['confirm_password']);

            if($password != $confirm_password){

                $confirm_password_err = 'Password did not match.';

            }

        }

        

        // Check input errors before inserting in database

        if(empty($username_err) && empty($password_err) && empty($confirm_password_err)){

            

            // Prepare an insert statement

            $sql = "INSERT INTO users (username, password) VALUES (?, ?)";

             

            if($stmt = mysqli_prepare($link, $sql)){

                // Bind variables to the prepared statement as parameters

                mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);

                

                // Set parameters

                $param_username = $username;

                $param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash

                

                // Attempt to execute the prepared statement

                if(mysqli_stmt_execute($stmt)){

                    // Redirect to login page

                    header("location: login.php");

                } else{

                    echo "Something went wrong. Please try again later.";

                }

            }

             

            // Close statement

            mysqli_stmt_close($stmt);

        }

        

        // Close connection

        mysqli_close($link);

    }

    ?>

     

    <!DOCTYPE html>

    <html lang="en">

    <head>

        <meta charset="UTF-8">

        <title>Sign Up</title>

        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
         <link rel="stylesheet" href="css/bootstrap.min.css">
        <style type="text/css">

             body{
                 font: 14px sans-serif;
            }
             .log_out{
                 background-image: url(image/8144_cool_sunrise.jpg);
                padding: 112px 0;
                background-color: violet;
                max-width: 1350px;
                max-height: 650px;

            }
            .wrapper{
                background-color: rgb(0,0,0,.5);
                padding: 63px 39px;
                border-radius: 9px 8px;
            }
            
           .wrapper h2{
               color: white;
               text-align: center;

            }
            .wrapper p{
                color: white;
            }
            .form-group{

            }
            label{
                color: white;
            }
            

        </style>

    </head>

    <body>
        
        
        <section class="log_out">
        <div class="container">
            <div class="raw">
            <div class="col-md-4"></div>
            <div class="col-md-4">


            <div class="wrapper">

                <h2><span style="color:#286090;font-size:40px;font-weight: unset;">S</span>ign Up</h2>

                <p>Please fill this form to create an account.</p>

                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">

                    <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">

                        <label>Username</label>

                        <input type="text" name="username"class="form-control" placeholder="Enter Name" value="<?php echo $username; ?>">

                        <span class="help-block"><?php echo $username_err; ?></span>

                    </div>    

                    <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">

                        <label>Password</label>

                        <input type="password" name="password" placeholder="Enter password" class="form-control" value="<?php echo $password; ?>">

                        <span class="help-block"><?php echo $password_err; ?></span>

                    </div>

                    <div class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">

                        <label>Confirm Password</label>

                        <input type="password" name="confirm_password" placeholder="Enter Confirm Password" class="form-control" value="<?php echo $confirm_password; ?>">

                        <span class="help-block"><?php echo $confirm_password_err; ?></span>

                    </div>

                    <div class="form-group">

                        <input type="submit" class="btn btn-primary" value="Submit">

                        <input type="reset" class="btn btn-default" value="Reset">

                    </div>

                    <p>Already have an account? <a href="login.php">Login here</a>.</p>

                </form>

            </div> 
            </div>

             <div class="col-md-4"></div>
            </div>
        </div>  
        </section> 

    </body>

    </html>

