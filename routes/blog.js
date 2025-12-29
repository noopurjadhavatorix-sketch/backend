const express = require("express");
const router = express.Router();
const { body } = require("express-validator");
const multer = require("multer");
const blogController = require("../controllers/blogController");
const { protect, authorize } = require("../middleware/auth");

// ---------------------- MULTER CONFIG ----------------------

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Only image files are allowed!"), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// ---------------------- VALIDATION RULES ----------------------

const blogValidationRules = [
  body("title").trim().notEmpty().withMessage("Title is required"),
  body("content").trim().notEmpty().withMessage("Content is required"),
  body("category").trim().notEmpty().withMessage("Category is required"),
  body("authorName").optional().trim(),
  body("status")
    .optional()
    .isIn(["draft", "published", "archived"])
    .withMessage("Invalid status"),
  body("tags").optional(),
  body("keywords").optional(),
  body("subcategory").optional().trim()
];

// ---------------------- ROUTES ----------------------

// CREATE POST
router.post(
  "/posts",
  protect,
  authorize("admin"),
  upload.fields([
    { name: "featuredImage", maxCount: 1 },
    { name: "bannerImage", maxCount: 1 }
  ]),
  blogValidationRules,
  blogController.createBlogPost
);

// GET ALL POSTS
router.get("/posts", blogController.getBlogPosts);

// GET SINGLE POST BY SLUG
router.get("/posts/:slug", blogController.getBlogPostBySlug);

// UPDATE POST
router.put(
  "/posts/:id",
  protect,
  authorize("admin", "editor"),
  upload.fields([
    { name: "featuredImage", maxCount: 1 },
    { name: "bannerImage", maxCount: 1 }
  ]),
  blogValidationRules,
  blogController.updateBlogPost
);

// DELETE POST (FIXED)
router.delete(
  "/posts/:id",
  protect,
  authorize("admin", "editor"),
  blogController.deleteBlogPost
);

module.exports = router;
