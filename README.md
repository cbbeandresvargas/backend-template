# backend docs

## security measurements

## **1. Auth and Tokens**  
**Description:**  
Control user access using secure authentication and token generation.  
**Implementation:**  
- Use `laravel/passport` or `tymondesigns/jwt-auth` for JWT handling.  
- Protect routes with `auth:api` middleware.  

**When to implement:** From the start, to secure routes immediately.  

## **2. Routes and Endpoints Protection**  
**Description:**  
Restrict routes based on roles or permissions and limit unauthorized access.  
**Implementation:**  
- Create custom middlewares (`php artisan make:middleware AdminMiddleware`).  
- Use policies (`php artisan make:policy PostPolicy`) and `Gate` for fine-grained access control.  
- Enable rate limiting with the `ThrottleRequests` middleware.  

**When to implement:** Alongside route development.  

## **3. Database and Data Protection**  
**Description:**  
Protect sensitive data and prevent SQL injections.  
**Implementation:**  
- Use parameterized queries (`DB::select('SELECT * FROM users WHERE email = ?', [$email])`).  
- Encrypt sensitive data with `encrypt()` and `decrypt()`.  
- Design secure migrations with constraints and default values.  

**When to implement:** During database schema design.  

## **4. Server Configuration and Laravel**  
**Description:**  
Secure the server and Laravel configuration to avoid data exposure.  
**Implementation:**  
- Set `APP_DEBUG=false` in production.  
- Force HTTPS using `RedirectIfAuthenticated`.  
- Limit permissions on `.env` files.  
- Add security headers with `bepsvpt/secure-headers`.  

**When to implement:** Before production deployment.  

## **5. Advanced Control of Access**  
**Description:**  
Manage roles, permissions, and advanced access restrictions.  
**Implementation:**  
- Use `spatie/laravel-permission` for dynamic role/permission management.  
- Implement account lockouts after multiple failed attempts (`max_attempts`).  
- Log sensitive actions for auditing.  

**When to implement:** During backend development.  

## **6. Intrusion Detection and Monitoring**  
**Description:**  
Detect suspicious activity and prevent malicious access.  
**Implementation:**  
- Log user actions with `spatie/laravel-activitylog`.  
- Set up email/Slack alerts for abnormal behavior.  
- Monitor Laravel logs (`storage/logs/laravel.log`).  

**When to implement:** Before production, but after feature development.  

## **7. CSRF Protection**  
**Description:**  
Protect forms and requests from Cross-Site Request Forgery (CSRF).  
**Implementation:**  
- Laravel includes CSRF protection by default with `@csrf` in forms.  
- Use the `VerifyCsrfToken` middleware to validate tokens.  

**When to implement:** From the start — Laravel has this enabled by default.  

## **8. Password and Data Encryption**  
**Description:**  
Ensure passwords and sensitive data are encrypted.  
**Implementation:**  
- Use `Hash::make()` for passwords.  
- Encrypt critical data with `Crypt::encrypt()`.  

**When to implement:** From the start.  

## **9. Two-Factor Authentication (2FA)**  
**Description:**  
Add an extra layer of user verification.  
**Implementation:**  
- Use `laravel/fortify` or `laravel/breeze` to handle 2FA via email, SMS, or authenticator apps.  

**When to implement:** After basic authentication setup.  

## **10. Environment Variable Security**  
**Description:**  
Secure `.env` files and prevent API key exposure.  
**Implementation:**  
- Use `APP_ENV=production`.  
- Restrict `.env` file permissions (`chmod 600`).  

**When to implement:** Before production.  

## **11. Secure Coding Practices**  
**Description:**  
Minimize human errors and vulnerabilities.  
**Implementation:**  
- Stick to the Single Responsibility Principle (SRP).  
- Disable debug routes and error outputs in production.  

**When to implement:** Throughout the development cycle.  

## **12. SQL Injection Prevention**  
**Description:**  
Prevent SQL injection attacks.  
**Implementation:**  
- Use Eloquent ORM or parameterized queries (`DB::select()`).  

**When to implement:** During query design.  

## **13. Input Sanitization and Validation**  
**Description:**  
Prevent XSS, script injections, and user-based attacks.  
**Implementation:**  
- Validate inputs with `$request->validate()`.  
- Escape outputs with `e()` or `{{ }}` in Blade.  

**When to implement:** Throughout development.  

## **14. Dependency Updates**  
**Description:**  
Fix vulnerabilities from outdated packages.  
**Implementation:**  
- Run `composer outdated` and `composer update` regularly.  

**When to implement:** Continuously, especially before production.  

## **15. Enable HTTPS and SSL**  
**Description:**  
Encrypt client-server communication.  
**Implementation:**  
- Set up an SSL certificate (Let’s Encrypt or similar).  
- Force HTTPS in Laravel configuration.  

**When to implement:** Before production.  

## **16. Penetration Testing and Static Code Analysis**  
**Description:**  
Identify security holes and weak code.  
**Implementation:**  
- Use OWASP ZAP, Nessus, or Laravel Security Checker.  
- Integrate static analysis tools like SonarQube.  

**When to implement:** Before final deployment.  




## steps
1. config the .env file (timezone, db)
2. install JWT
```bash
composer require tymon/jwt-auth
```
3. publish the JWT config
```bash
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```
4. generate the JWT secret key (the secret key will appear in the .env file)
```bash
php artisan jwt:secret
```
5. install api (dont execute the migration)
```bash
php artisan install:api
```
6. edit the file config/auth.php
```php
'defaults' => [
        'guard' => env('AUTH_GUARD', 'api'),
        'passwords' => env('AUTH_PASSWORD_BROKER', 'users'),
    ],
'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
        'api' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ],
    ],
```
7. in the file app/models/user.php change the class to:
```php
class User extends Authenticatable implements JWTSubject
```
8. get sure that the library imports
```php
use Tymon\JWTAuth\Contracts\JWTSubject;
```
9. paste the functions inside of the class
```php
public function getJWTIdentifier()
    {
        return $this->getKey();
    }
public function getJWTCustomClaims()
    {
        return [];
    }
```
10. change the user migration in database/migrations/create_users_table.php to add the user role
```php
$table->string('role',20);
```
11. edit the model of the user app/models/user.php to add the role data
```php
protected $fillable = [
        'name',
        'role',
        'email',
        'password',
    ];
```
12. create the middlewares
```bash
php artisan make:middleware IsUserAuth
php artisan make:middleware IsAdmin
```
13. create a table for something in the db (this will create a model, migration and controller)(for the example the model will be Products)
```bash
php artisan make:model Product -mc
```
14. edit the migration to put the data schema database/migrations/create_products_table.php
```php
Schema::create('products', function (Blueprint $table) {
            $table->id();
            $table->string('name', 255);
            $table->decimal('price', 8,2);
            $table->timestamps();
        });
```
15. edit the model app/models/product.php
```php
class Product extends Model
{
    use HasFactory;
    protected $fillable = ['name','price'];
}
```
16. get sure that the libray is imported
```php
use Illuminate\Database\Eloquent\Factories\Hasfactory;
```
17. create the auth controller
```bash
php artisan make:controller AuthController
```
18. edit the controllers to add the CRUD functions and validations first for validation we need the library
```php
use Illuminate\Support\Facades\Validator;
```

19. in this example the ProductController.php will be edit to make a CRUD
* create a product
```php
public function addProduct(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|min:10|max:100',
            'price' => 'required|numeric',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        Product::create([
            'name' => $request->get('name'),
            'price' => $request->get('price'),
        ]);

        return response()->json(['message' => 'Product added successfully'], 201);
    }
```
* get all products
```php
public function getProducts(){
        $products = Product::all();
        if($products->isEmpty()){
            return response()->json(['message'=>'no products found'], 404);
        }else{
            return response()->json($products, 200);
        }
    }
```
* get all products with pagination
```php
public function getProducts(Request $request)
    {
        $limit = (int) $request->query('limit', 20);
        $products = Product::paginate($limit);

        if ($products->isEmpty()) {
            return response()->json(['message' => 'No products found'], 404);
        }

        return response()->json($products, 200);
    }
```
* get product by id
```php
public function getProductById($id)
    {
        $product = Product::find($id);

        if (!$product) {
            return response()->json(['message' => 'Product not found'], 404);
        }

        return response()->json($product, 200);
    }
```
* update product by id
```php
public function updateProduct(Request $request, $id)
    {
        $product = Product::find($id);

        if (!$product) {
            return response()->json(['message' => 'Product not found'], 404);
        }

        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|string|min:10|max:100',
            'price' => 'sometimes|numeric',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        if ($request->has('name')) {
            $product->name = $request->name;
        }

        if ($request->has('price')) {
            $product->price = $request->price;
        }

        $product->save();

        return response()->json(['message' => 'Product updated successfully'], 200);
    }
```
* delete a product by id
```php
public function deleteProductById($id)
    {
        $product = Product::findOrFail($id);

        $product->delete();

        return response()->json(['message' => 'Product deleted successfully'], 200);
    }
```
20. create the model, migration and controller of the files
```bash
php artisan make:model Files -mc
```
21. edit the migration to create the files table
```php
Schema::create('files', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('route');
            $table->timestamps();
        });
```
22. edit the model of the files app/models/files.php
```php
use HasFactory;
    protected $fillable = ['name','route'];
```
23. get sure that the libray is imported
```php
use Illuminate\Database\Eloquent\Factories\Hasfactory;
```
24. edit the .env file
```
APP_URL=http://localhost:8000

FILESYSTEM_DISK=public

```
25. import the library of the validator in the image controller
```php
use Illuminate\Support\Facades\Validator;
```
25. edit the files controller to add the CRUD functions and validations
* add a file
```php
public function addFile(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'  => 'required|string|min:10|max:100',
            'route' => 'required|file|mimes:png,jpeg,jpg,pdf|max:4096',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        if ($request->hasFile('route')) {
            $fileRoute = $request->file('route')->storeAs('uploads', uniqid() . '.' . $request->file('route')->extension());

            $file = new Files();
            $file->name = $request->name;
            $file->route = $fileRoute;
            $file->save();

            return response()->json(['message' => 'File added successfully'], 201);
        }

        return response()->json(['error' => 'File upload failed'], 500);
    }
```
* get files
```php
public function getFiles()
    {
        $files = Files::all();
        if ($files->isEmpty()) {
            return response()->json(['message' => 'No files found'], 404);
        }

        foreach ($files as $file) {
            $file->route = asset(Storage::url($file->route));
        }

        return response()->json($files, 200);
    }
```
* get file by id
```php
public function getFileById($id)
    {
        $file = Files::find($id);
        if (!$file) {
            return response()->json(['message' => 'File not found'], 404);
        }

        $file->route = asset(Storage::url($file->route));
        return response()->json($file, 200);
    }
```
* update a file by id
```php
public function updateFileById($id, Request $request)
    {
        $file = Files::find($id);
        if (!$file) {
            return response()->json(['message' => 'File not found'], 404);
        }

        $validator = Validator::make($request->all(), [
            'name'  => 'sometimes|string|min:10|max:100',
            'route' => 'sometimes|file|mimes:png,jpeg,jpg,pdf|max:4096',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        if ($request->has('name')) {
            $file->name = $request->name;
        }

        if ($request->hasFile('route')) {
            if ($file->route && Storage::exists($file->route)) {
                Storage::delete($file->route);
            }

            $fileRoute = $request->file('route')->storeAs('uploads', uniqid() . '.' . $request->file('route')->extension());
            $file->route = $fileRoute;
        }

        $file->save();

        return response()->json(['message' => 'File updated successfully'], 200);
    }
```
* delete file by id
```php
public function deleteFileById($id)
    {
        $file = Files::find($id);
        if (!$file) {
            return response()->json(['message' => 'File not found'], 404);
        }

        if ($file->route && Storage::exists($file->route)) {
            Storage::delete($file->route);
        }

        $file->delete();

        return response()->json(['message' => 'File deleted successfully'], 200);
    }
```
26. make a migration
```bash
php artisan migrate
```
27. create a direct access to the files folder
```bash
php artisan storage:link
```
28. all the files uploades will be on the folder: public/storage/uploads that is goona be linked to the folder: storage/app/public/uploads
29. enable the following extensions in the php configuration in the server:
* extension=curl
* extension=fileinfo
* extension=gd
* extension=mbstring
* extension=openssl
* extension=mysql
* extension=zip
30. configure the api routes in the file: routes/api.php
```php
Route::controller(FileController::class)->group(function (){
    Route::post('files', 'addFile');
    Route::get('files', 'getFiles');
    Route::get('files/{id}', 'getFileById');
    Route::post('files/{id}', 'updateFileById');
    Route::delete('files/{id}', 'deleteFileById');
});
```
31. get sure that the controller is imported
```php
use App\Http\Controllers\FilesController;
```
32. to see all the routes in console you can use the comand:
```bash
php artisan route:list
```
33. once the image crud is ready you need to continue with the AuthController.php
34. here you create the CRUD for the user table with the login and logout
35. get sure that all libraries are imported
```php
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
```
36. create the functions:
* register user
```php
public function register(Request $request){
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|min:10|max:100',
            'role'=> 'required|string|in:admin,user',
            'email' => 'required|email|min:10|max:50|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        User::create([
            'name' => $request->get('name'),
            'role' => $request->get('role'),
            'email' => $request->get('email'),
            'password' => bcrypt($request->get('password')),
        ]);

        return response()->json(['message' => 'User registered successfully'], 201);
    }
```
* login user
```php
public function login(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|min:10|max:50|exists:users',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        $credentials = $request->only(['email', 'password']);

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'Invalid credentials'], 401);
            }

            return response()->json(['token' => $token], 200);

        } catch (JWTException $e) {
            return response()->json(['error' => 'Could not create auth token', 'exception' => $e->getMessage()], 500);
        }
    }
```
* get user
```php
public function getUser(){
        $user = auth()->user();
        return response()->json($user, 200);
    }
```
* logout user
```php
public function logOut(){
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message' => 'User logged out successfully'], 200);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Failed to log out', 'exception' => $e->getMessage()], 500);
        }
    }
```
37. now we are going to configurate the middlewares we configured previously, this are in the route: app/http/middleware
38. first the IsUserAuth.php middleware
```php
public function handle(Request $request, Closure $next): Response
    {
        if(auth('api')->user()){
            return $next($request);
        }else{
            return response()->json(['message' => 'Unauthorized'], 401);
        }
    }
```
39. now the IsAdmin.php middleware
```php
public function handle(Request $request, Closure $next): Response
    {
        $user = auth('api')->user();
        if($user && $user->role === 'admin'){
            return $next($request);
        }else{
            return response()->json(['message'=>'You are not authorized to perform this action'], 403);
        }
    }
```
40. now we need to put the middlewares in the file: bootstrap/app.php
41. first import the middlewares
```php
use App\Http\Middleware\IsAdmin;
use App\Http\Middleware\IsUserAuth;
```
42. now config the function of the middleware
```php
return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        IsUserAuth::class;
        IsAdmin::class;
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })->create();
```
43. now we need to configurate the routes, first import the controllers an middlewares
```php
use App\Http\Controllers\AuthController;
use App\Http\Controllers\ProductController;
use App\Http\Controllers\FilesController;
use App\Http\Middlewares\IsUserAuth;
use App\Http\Middlewares\IsAdmin;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
```
44. first the public routes
```php
//public routes
Route::post('register', AuthController::class, 'register');
Route::post('login', AuthController::class, 'login');
```
45. then the private routes
```php
//private routes
Route::middleware([IsUserAuth::class])->group(function(){
    Route::controller(AuthController::class)->group(function (){
        Route::post('logout', 'logout');
        Route::get('me', 'getUser');
    });

    Route::get('products', [ProductController::class, 'getProducts']);

    Route::middleware([IsAdmin::class])->group(function(){
        Route::controller(ProductController::class)->group(function (){
            Route::post('products', 'addProduct');
            Route::get('products', 'getProducts');
            Route::get('products/{id}', 'getProductById');
            Route::patch('products/{id}', 'updateProductById');
            Route::delete('products/{id}', 'deleteProductById');
        });
    });
});
```
46. now we need to make a migration
```bash
php artisan migrate
```