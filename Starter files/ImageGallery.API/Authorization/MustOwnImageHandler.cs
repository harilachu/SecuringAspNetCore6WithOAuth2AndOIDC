using ImageGallery.API.Services;
using Microsoft.AspNetCore.Authorization;

namespace ImageGallery.API.Authorization
{
    public class MustOwnImageHandler : AuthorizationHandler<MustOwnImageRequirement>
    {
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly IGalleryRepository galleryRepository;

        public MustOwnImageHandler(IHttpContextAccessor httpContextAccessor, IGalleryRepository galleryRepository)
        {
            this.httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
            this.galleryRepository = galleryRepository ?? throw new ArgumentNullException(nameof(galleryRepository));
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, 
            MustOwnImageRequirement requirement)
        {
            var imageId = httpContextAccessor.HttpContext?.GetRouteValue("id")?.ToString();

            if(!Guid.TryParse(imageId, out var imageIdAsGuid)) 
            {
                context.Fail();
                return;
            }

            var ownerId = context.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            if(ownerId == null)
            {
                context.Fail();
                return;
            }

            if(!await galleryRepository.IsImageOwnerAsync(imageIdAsGuid, ownerId))
            {
                context.Fail();
                return;
            }

            context.Succeed(requirement);
        }
    }
}
