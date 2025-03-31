<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\ProductController;
use App\Http\Controllers\FilesController;
use App\Http\Middleware\IsUserAuth;
use App\Http\Middleware\IsAdmin;
use Illuminate\Support\Facades\Route;

// Rutas públicas
Route::post('register', [AuthController::class, 'register']);
Route::post('login', [AuthController::class, 'login']);

// Rutas protegidas (requieren autenticación)
Route::middleware([IsUserAuth::class])->group(function () {

    Route::post('logout', [AuthController::class, 'logout']);
    Route::get('me', [AuthController::class, 'getUser']);

    // Rutas de productos accesibles para usuarios autenticados
    Route::get('products', [ProductController::class, 'getProducts']);

    // Rutas solo para administradores
    Route::middleware([IsAdmin::class])->group(function () {
        Route::post('products', [ProductController::class, 'addProduct']);
        Route::get('products/{id}', [ProductController::class, 'getProductById']);
        Route::patch('products/{id}', [ProductController::class, 'updateProductById']);
        Route::delete('products/{id}', [ProductController::class, 'deleteProductById']);
    });
});

// Rutas de archivos
Route::controller(FilesController::class)->group(function () {
    Route::post('files', 'addFile');
    Route::get('files', 'getFiles');
    Route::get('files/{id}', 'getFileById');
    Route::post('files/{id}', 'updateFileById');
    Route::delete('files/{id}', 'deleteFileById');
});
